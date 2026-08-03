# infra-sync-api

API intermediaria em FastAPI para sincronizar hosts do Zabbix com o NetBox, com integracao pensada para o n8n.

## Arquitetura

- `app/main.py`: aplica a API FastAPI, autenticacao por `X-API-Key` e rotas.
- `app/services.py`: orquestracao da sincronizacao e modo `dry-run`.
- `app/netbox_client.py`: cliente HTTP assíncrono para o NetBox.
- `app/models.py`: validacao do payload de entrada.
- `app/utils.py`: slug, IP e merge de `custom_fields`.
- `tests/`: testes unitarios da logica pura.

## Instalação

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

Preencha `NETBOX_TOKEN` e `SYNC_API_KEY` no arquivo `.env`.

Se `NETBOX_TOKEN` estiver vazio, a aplicacao deve ser tratada como incompleta e o container nao deve subir.

## Variáveis

- `NETBOX_URL`: URL base do NetBox.
- `NETBOX_TOKEN`: token da API do NetBox.
- `SYNC_API_KEY`: chave para `X-API-Key`.
- `ZABBIX_URL`: endpoint JSON-RPC do Zabbix.
- `ZABBIX_TOKEN`: token bearer do Zabbix API.
- `DEFAULT_SITE_ID`: site padrao se o payload nao trouxer valor util.
- `DEFAULT_ROLE_ID`: role padrao para o fluxo Zabbix.
- `DEFAULT_ACCESS_POINT_ROLE_ID`: role usada quando o Zabbix indicar access point.
- `REQUEST_TIMEOUT`: timeout HTTP em segundos.
- `ZABBIX_TIMEOUT`: timeout HTTP em segundos para o Zabbix.
- `LOG_LEVEL`: nivel de log.
- `ALLOWED_CLIENT_CIDRS`: redes autorizadas a chamar a API.

- `NETBOX_TOKEN` pode ser informado cru ou já com prefixo `Bearer ` ou `Token `.

## Endpoints

- `GET /` -> redireciona para `/docs`
- `GET /health`
- `GET /version`
- `POST /sync/device`
- `POST /sync/device/dry-run`
- `POST /sync/zabbix/device`
- `POST /sync/zabbix/device/dry-run`

## Exemplos

### Health

```bash
curl http://127.0.0.1:8088/health
```

### Version

```bash
curl http://127.0.0.1:8088/version
```

### Sync real

```bash
curl -X POST http://127.0.0.1:8088/sync/device \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <SYNC_API_KEY>" \
  -d '{
    "hostid": "10917",
    "hostname": "SW-CCO-GDS7830",
    "display_name": "SW-CCO-GDS7830",
    "ip": "10.0.0.24",
    "fabricante": "GENERICO",
    "modelo": "Switch Gerenciavel Generico",
    "site_id": 1,
    "role_id": 2,
    "zabbix_status": "0"
  }'
```

### Dry-run

```bash
curl -X POST http://127.0.0.1:8088/sync/device/dry-run \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <SYNC_API_KEY>" \
  -d '{
    "hostid": "10917",
    "hostname": "SW-CCO-GDS7830",
    "display_name": "SW-CCO-GDS7830",
    "ip": "10.0.0.24",
    "fabricante": "GENERICO",
    "modelo": "Switch Gerenciavel Generico",
    "site_id": 1,
    "role_id": 2,
    "zabbix_status": "0"
  }'
```

### Sync from Zabbix

```bash
curl -X POST http://127.0.0.1:8088/sync/zabbix/device \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <SYNC_API_KEY>" \
  -d '{
    "hostid": "10917",
    "site_id": 1,
    "role_id": 2
  }'
```

Esse fluxo consulta o host no Zabbix, usa o inventario e as interfaces SNMP
disponiveis e alimenta o NetBox com o que for encontrado.

## n8n

HTTP Request node:

- Method: `POST`
- URL: `http://10.254.0.115:8088/sync/device`
- Headers:
  - `Content-Type: application/json`
  - `X-API-Key: <SYNC_API_KEY>`
- Body em Expression:

```javascript
={{
  {
    hostid: String($json.hostid),
    hostname: $json.hostname,
    display_name: $json.display_name || $json.hostname,
    ip: $json.ip,
    fabricante: $json.fabricante,
    modelo: $json.modelo,
    site_id: Number($json.site_id),
    role_id: Number($json.role_id),
    zabbix_status: String($json.zabbix_status || '')
  }
}}
```

### Zabbix-driven n8n

Quando o passo anterior so precisar informar o `hostid`, use o endpoint novo:

- Method: `POST`
- URL: `http://10.254.0.115:8088/sync/zabbix/device`
- Headers:
  - `Content-Type: application/json`
  - `X-API-Key: <SYNC_API_KEY>`
- Body em Expression:

```javascript
={{
  {
    hostid: String($json.hostid),
    site_id: Number($json.site_id || 1),
    role_id: Number($json.role_id || 2)
  }
}}
```

## Atualização

```powershell
git pull
pip install -r requirements.txt
docker compose build
docker compose up -d
```

## Logs

```bash
docker compose logs -f infra-sync-api
```

## Reinício

```bash
docker compose restart infra-sync-api
```

## Backup

Antes de sobrescrever a pasta em produção:

```bash
timestamp=$(date +%Y%m%d-%H%M%S)
mkdir -p /opt/backups/infra-sync-api/$timestamp
cp -a /opt/infra-sync-api/. /opt/backups/infra-sync-api/$timestamp/
```

## Reversão

```bash
rsync -a /opt/backups/infra-sync-api/<timestamp>/ /opt/infra-sync-api/
docker compose up -d --build
```

## Docker Compose

O `compose.yaml` usa:

- `container_name: infra-sync-api`
- `restart: unless-stopped`
- `network_mode: host` para preservar o IP real do cliente
- `env_file: .env`
- healthcheck local
- logging `json-file` com limite de tamanho

## Observações

- A API nao expõe `NETBOX_TOKEN` nem `SYNC_API_KEY` em log.
- O modo `dry-run` consulta o NetBox, mas nao cria nem atualiza nada.
- O fluxo real valida `site_id` e `role_id` no NetBox antes de criar qualquer objeto.
- Cada sync real grava um marcador no campo `description` do Device com hostid, acao e timestamp UTC.
- Devices existentes em estado `planned` sao promovidos para `active` na sincronizacao, para ficar visivel na listagem do NetBox.
- O fluxo Zabbix consulta o host, inventario e interfaces SNMP antes de sincronizar o Device.
- O fluxo Zabbix usa `status=active` quando o host esta habilitado no Zabbix e `planned` quando esta desabilitado.
- A criacao real do Device deve ser feita somente com autorizacao.
- Requisicoes fora de `127.0.0.1/32`, `10.254.0.0/24` e `10.0.0.115/32` recebem `403`.
