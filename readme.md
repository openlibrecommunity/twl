<div align="center">

<img src="asset/logo.png" width="150">

![License](https://img.shields.io/badge/license-BSD--3--Clause-0D1117?style=flat-square&logo=open-source-initiative&logoColor=green&labelColor=0D1117)
![Golang](https://img.shields.io/badge/-Golang-0D1117?style=flat-square&logo=go&logoColor=00A7D0)

</div>

## About

Периодически обновляемые списки IP-адресов с открытым портом 443 для российских и СНГ-провайдеров. Можно использовать как whitelist в роутере/файрволе или для проверки есть ли ваш IP в бс ( для этого лучше подойдет [наш бот](https://t.me/olcwlybot) или [наш API](https://wly.zarazaex.xyz/check?ip=1.1.1.1) который в реальном времени проверяет отвечает ли ваш IP с симки )

## Где что лежит

| Файл | Описание |
|------|----------|
| [code/scan/out/whitelist_ips.txt](code/scan/out/whitelist_ips.txt) | Все найденные IP (сырые) |
| [code/scan/out/verify/verified.txt](code/scan/out/verify/verified.txt) | Проверенные IP |
| [code/sort/out/sorted.json](code/sort/out/sorted.json) | IP сгруппированные по ASN (сырые) |
| [code/sort/out/sorted.c.json](code/sort/out/sorted.c.json) | IP сгруппированные по ASN (проверенные) |
| [code/subnet/out/subnets.json](code/subnet/out/subnets.json) | Подсети (сырые) |
| [code/subnet/out/subnets.c.json](code/subnet/out/subnets.c.json) | Подсети (проверенные) |

</details>

<div align="center">

---

### Contact

Telegram: [zarazaex](https://t.me/zarazaexe)
<br>
Email: [zarazaex@tuta.io](mailto:zarazaex@tuta.io)
<br>
Site: [zarazaex.xyz](https://zarazaex.xyz)
<br>

</div>
