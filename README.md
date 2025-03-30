# Трассировка автономных систем

## Автор
Султанов Андрей КН-201

## Описание проекта
Консольное приложение для анализа маршрута трассировки с определением автономных систем. Программа выполняет трассировку до указанного узла и определяет для каждого маршрутизатора:
- Номер автономной системы (AS)
- Страну расположения
- Интернет-провайдера

## Установка
1. Установите необходимые библиотеки:
```bash
pip install ipwhois prettytable
```
2. Склонируйте репозиторий
```bash
git clone https://github.com/Andrew80t7/Trace.git
cd Trace
```
## Использование
```bash
python main.py <целевой_адрес>
```
Где <целевой_адрес> может быть:
- IP-адрес (например, 8.8.8.8)
- Доменное имя (например, google.com)

## Примеры
1. Трассировка до домена Google:
```bash
python main.py google.com
```
2. Трассировка до DNS-сервера Google:
```bash
python traceroute_as.py 8.8.8.8
```
## Формат вывода:
```Tracing route to "google.com":

+----+-----------------+-------+---------+-------------------+
| No |       IP        |  AS   | Country |     Provider      |
+----+-----------------+-------+---------+-------------------+
| 1  | 192.168.1.1     |   -   |    -    |        -          |
| 2  | 10.88.96.1      |   -   |    -    |        -          |
| 3  | 194.186.136.45  | 1234  |   RU    |   Rostelecom      |
| 4  | 72.14.212.118   | 15169 |   US    |   Google LLC      |
+----+-----------------+-------+---------+-------------------+

Tracing completed.```
