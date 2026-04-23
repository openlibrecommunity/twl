---
tags:
  - whitelist
  - l3
  - l7
  - sni
type: concept
---

# Механизм белого списка

## L3 (IP)

Первичная фильтрация. Если IP не в белом списке — TCP соединение не устанавливается.

```
curl --interface wlan0 --resolve "ya.ru:443:149.154.167.99" https://ya.ru
# 149.154.167.99 = telegram (не белый IP)
# Результат: connection failed (000)
```

## L7 (SNI)

Вторичная фильтрация. Если IP белый, проверяется SNI в TLS ClientHello.

```
curl --interface wlan0 --resolve "telegram.org:443:77.88.44.242" https://telegram.org
# 77.88.44.242 = yandex (белый IP)
# SNI = telegram.org (не белый)
# Результат: 406
```

```
curl --interface wlan0 --resolve "ya.ru:443:77.88.44.242" https://ya.ru  
# Белый IP + белый SNI
# Результат: 302 (работает)
```

## Порядок проверки

1. IP whitelist (L3) — дроп если не в списке
2. SNI whitelist (L7) — дроп если домен не в списке
