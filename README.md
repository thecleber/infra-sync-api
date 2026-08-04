# infra-sync-api

Painel central em FastAPI para operacao de rede em uma unica interface, com foco em NetBox, Zabbix, GLPI e n8n.

O projeto entrega:

- dashboard na raiz;
- pagina de configuracao para URLs, tokens e SMTP de alertas;
- configuracao de atualizacao automatica com intervalo em segundos, minutos, horas ou dias;
- snapshot operacional com contadores do inventario;
- endpoints de sincronizacao para automacao.
- paginas para devices, VLANs, redes, alertas e relatórios;
- consulta de alertas do Zabbix em tempo real;
- formulÃ¡rios para criar e editar devices, VLANs e prefixes no NetBox.

## Estrutura

- `app/main.py`: ponto de entrada.
- `app/new_main.py`: dashboard, configuracao, health e rotas de sync.
- `app/services.py`: orquestracao da sincronizacao e modo dry-run.
- `app/netbox_client.py`: cliente assicrono do NetBox.
- `app/zabbix_client.py`: cliente JSON-RPC do Zabbix.
- `app/models.py`: validacao dos payloads.
- `app/utils.py`: slug, IP e merge de `custom_fields`.
- `tests/`: testes de dashboard e validacao.

## Instalacao

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

Preencha `NETBOX_TOKEN` e `SYNC_API_KEY` no arquivo `.env`.

Se `NETBOX_TOKEN` estiver vazio, a aplicacao deve ser tratada como incompleta.

O sistema tambem salva configuracoes editaveis em `data/integrations.json`, via pagina `/settings`.

## Variaveis

- `NETBOX_URL`: URL base do NetBox.
- `NETBOX_TOKEN`: token da API do NetBox.
- `SYNC_API_KEY`: chave usada em `X-API-Key`.
- `ZABBIX_URL`: endpoint JSON-RPC do Zabbix.
- `ZABBIX_TOKEN`: token bearer do Zabbix.
- `DEFAULT_SITE_ID`: site padrao.
- `DEFAULT_ROLE_ID`: role padrao.
- `DEFAULT_ACCESS_POINT_ROLE_ID`: role para access point.
- `REQUEST_TIMEOUT`: timeout HTTP em segundos.
- `ZABBIX_TIMEOUT`: timeout HTTP para o Zabbix.
- `LOG_LEVEL`: nivel de log.
- `ALLOWED_CLIENT_CIDRS`: redes autorizadas a chamar a API.

## Endpoints

- `GET /` -> dashboard central.
- `GET /dashboard` -> mesmo dashboard.
- `GET /settings` -> pagina de configuracao.
- `POST /settings` -> configura também o e-mail de alertas.
- `POST /settings` -> salva a configuracao local e recarrega os conectores.
- `GET /api/config` -> configuracao mascarada.
- `GET /api/overview` -> snapshot operacional.
- `GET /devices` -> lista e edita devices.
- `POST /devices/save` -> cria ou atualiza um device.
- `GET /vlans` -> lista e edita VLANs.
- `POST /vlans/save` -> cria ou atualiza uma VLAN.
- `GET /networks` -> lista e edita prefixes/redes.
- `POST /networks/save` -> cria ou atualiza um prefix.
- `GET /alerts` -> painel de alertas em tempo real.
- `GET /cpd` -> painel fixo para CPD com atualizacao visual a cada 2 segundos.
- `POST /alerts/email/send` -> envia um resumo dos alertas atuais por e-mail.
- `GET /api/alerts` -> JSON com os problemas abertos no Zabbix.
- `GET /reports` -> relatÃ³rio imprimÃ­vel.
- `GET /health`
- `GET /version`
- `POST /sync/device`
- `POST /sync/device/dry-run`
- `POST /sync/zabbix/device`
- `POST /sync/zabbix/device/dry-run`

## O que o sistema mostra

- status do NetBox, Zabbix, GLPI e n8n;
- contagem de devices, IPs, VLANs, interfaces, prefixes, sites, racks e hosts do Zabbix;
- painel para editar URLs e tokens sem parar a aplicacao;
- painel para ajustar a frequencia de atualizacao dos dados exibidos;
- cadastro e ediÃ§Ã£o manual de devices, VLANs e redes dentro da prÃ³pria interface;
- painel de alertas do Zabbix com atualização periódica;
- painel CPD dedicado para monitorar servidores, roteadores, switches, links e servicos criticos em tela fixa;
- alerta sonoro configur?vel por severidade no painel de alertas;
- configuração de SMTP e disparo manual do resumo dos alertas por e-mail;
- relatório imprimível com os principais indicadores;
- rotas de sync para alimentar o inventario central.

## Exemplos

### Health

```bash
curl http://127.0.0.1:8088/health
```

### Dashboard

```bash
curl http://127.0.0.1:8088/
```

### Configuracao

```bash
curl http://127.0.0.1:8088/api/config
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

## n8n

HTTP Request node:

- Method: `POST`
- URL: `http://10.0.0.115:8088/sync/device`
- Headers:
  - `Content-Type: application/json`
  - `X-API-Key: <SYNC_API_KEY>`

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

## Atualizacao

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

## Reinicio

```bash
docker compose restart infra-sync-api
```

## Observacoes

- A API nao expoe `NETBOX_TOKEN` nem `SYNC_API_KEY` em log.
- O modo `dry-run` consulta o NetBox, mas nao cria nem atualiza nada.
- O dashboard exibe os conectores e os contadores do ambiente quando eles estao configurados.
- A pagina `/settings` permite trocar tokens e URLs sem reiniciar o sistema.
- Requisicoes fora das redes autorizadas recebem `403`.

