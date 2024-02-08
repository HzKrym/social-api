## Описание публичного API

Если вам пришел 400 код в запросе, значит, вы не указали обязательные параметры.

### Регистрация

Для регистрации используем POST-запрос ```/register```.

В тело запроса передаются следующие аргументы:
``` JSON
{
    // Никнейм
    "username": "String",
    // Пароль
    "password": "String",
    // Фамилия(необязательно)
    "last_name": "String",
    // Имя(необязательно)
    "first_name": "String"
}
```

В качестве ответа вам придет следующая JSON:
``` JSON
{
    // ID нового пользователя
    "id": 0
}
```

Если вам пришел 401 код, значит, такой пользователь уже существует.

### Авторизация

Для авторизации(логина) используем POST-запрос ```/login```.

В тело запроса передаются следующие аргументы:
``` JSON
{
    // Никнейм
    "username": "String",
    // Пароль
    "password": "String"
}
```

В качестве ответа вам придет следующая JSON:
``` JSON
{
    // ID авторизованного пользователя
    "id": 0
}
```

Если вам пришел 401 код, значит, имя пользователя или пароль неверные.

### Получение последних сообщений

Для получения списка последних сообщений пользователя используем POST-запрос ```/message```.

В тело запроса передаются следующие аргументы:
``` JSON
{
    // ID пользователя
    "user_id": 0
}
```

В качестве ответа вам придет следующая JSON:
```JSON
{
    // Массив сообщений
    "last_messages": [
        {
            // ID сообщения
            "id": 0,
            // Текст сообщения
            "message": "String",
            // От кого сообщение
            "from": {
                "id": 0,
                "username": "String",
                "last_name": "String",
                "first_name": "String"
            },
            // Кому сообщение
            "to": {
                "id": 0,
                "username": "String",
                "last_name": "String",
                "first_name": "String"
            },
            // Время и дата отправки
            "datetime": "String"
        },
        ...
    ]
}
```

### Получение сообщений от пользователя

Для получения списка последних сообщений пользователя от другого пользователя используем POST-запрос ```/user-message```.

В тело запроса передаются следующие аргументы:
``` JSON
{
    // ID пользователя
    "user_id": Int,
    // ID другого пользователя
    "friend_id": Int
}
```

В качестве ответа вам придет следующая JSON:
```JSON
{
    // Массив сообщений
    "messages_list": [
        {
            // ID сообщения
            "id": 0,
            // Текст сообщения
            "message": "String",
            // От кого сообщение
            "from": {
                "id": 0,
                "username": "String",
                "last_name": "String",
                "first_name": "String"
            },
            // Кому сообщение
            "to": {
                "id": 0,
                "username": "String",
                "last_name": "String",
                "first_name": "String"
            },
            // Время и дата отправки
            "datetime": "String"
        },
        ...
    ]
}
```

### Отправка сообщения

Для отправки сообщения используем POST-запрос ```/send```.

В тело запроса передаются следующие аргументы:
``` JSON
{
    // ID пользователя, который отправляет сообщения
    "from": 0,
    // ID пользователя, которому отправляется сообщение
    "to": 0,
    // Сообщение
    "message": "String"
}
```

Если пришел 204 код, значит, сообщение отправилось.

### Поиск пользователя

Чтобы найти пользователя по строковому запросу используем POST-запрос ```/search```

В тело запроса передаются следующие аргументы:
``` JSON
{
    // Строка поиска
    "search_string": "String"
}
```

В качестве ответа вам придет следующая JSON:
```JSON
{
    "search_users": [
        {
            "id": 0,
            "username": "String"
            "last_name": "String",
            "first_name": "String",
        }
    ]
}
```

### Получение информации о пользователе

Для получения информации о пользователе используем GET-запрос ```/user/<username>```, где вместо username необходимо передать никнейм или ID пользователя.

В качестве ответа придет следующая JSON:
``` JSON
{
    // ID пользователя
    "id": 0,
    // Никнейм
    "username": "String",
    // Фамилия
    "last_name": "String",
    // Имя
    "first_name": "String"
}
```