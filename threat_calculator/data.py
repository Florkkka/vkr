ASSET_TYPES = [
    {"id": "controller", "name": "Контроллер / хаб", "icon": "hdd-network"},
    {"id": "network", "name": "Сетевое устройство (роутер и т.п.)", "icon": "wifi"},
    {"id": "sensor", "name": "Датчик", "icon": "thermometer-half"},
    {"id": "camera", "name": "Камера", "icon": "camera-video"},
    {"id": "lock", "name": "Замок / дверь", "icon": "shield-lock"},
    {"id": "cloud", "name": "Облачный сервис", "icon": "cloud"},
    {"id": "actuator", "name": "Исполнительное устройство (лампа, реле)", "icon": "lightbulb"},
    {"id": "voice", "name": "Голосовой ассистент", "icon": "mic"},
]

PROTOCOLS = ["Wi-Fi", "ZigBee", "Z-Wave", "Bluetooth", "Ethernet", "LoRaWAN", "Thread", "Matter"]

THREAT_TEMPLATES = [
    {
        "name": "Несанкционированный доступ к устройству",
        "stride": "E",
        "description": "Злоумышленник получает физический или удалённый доступ к устройству умного дома",
        "default_p": 2,
        "default_i": 3,
    },
    {
        "name": "DDoS-атака на устройство",
        "stride": "D",
        "description": "Блокирование доступа к устройству или сервису путём перегрузки запросами",
        "default_p": 2,
        "default_i": 2,
    },
    {
        "name": "Перехват сетевого трафика",
        "stride": "I",
        "description": "Прослушивание и анализ трафика между устройствами умного дома",
        "default_p": 2,
        "default_i": 2,
    },
    {
        "name": "Вредоносное ПО на контроллере",
        "stride": "T",
        "description": "Заражение центрального контроллера вредоносным ПО через уязвимости",
        "default_p": 1,
        "default_i": 3,
    },
    {
        "name": "Подмена устройства в сети",
        "stride": "S",
        "description": "Злоумышленник подключает поддельное устройство, выдавая себя за легитимное",
        "default_p": 2,
        "default_i": 3,
    },
    {
        "name": "Утечка данных через облачный сервис",
        "stride": "I",
        "description": "Компрометация данных пользователя через уязвимость облачного сервиса",
        "default_p": 2,
        "default_i": 3,
    },
    {
        "name": "Несанкционированное изменение конфигурации",
        "stride": "T",
        "description": "Изменение настроек устройств без ведома владельца",
        "default_p": 2,
        "default_i": 2,
    },
    {
        "name": "Отказ в обслуживании (DoS)",
        "stride": "D",
        "description": "Локальная атака на отказ в обслуживании устройства умного дома",
        "default_p": 2,
        "default_i": 2,
    },
]
