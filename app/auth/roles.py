roles = {
    "admin": {
        "max_queries": None, #consultas ilimitadas 
        "token_duration": 24 * 60 , #un día de duración 
        "access_schedule": None,
    },
    "usuario": {
        "max_queries": 3,  # 3 consultas diarias
        "token_duration": 1,  # 12 horas en minutos
        "access_schedule": {"start": 9, "end": 19},  # Acceso entre las 9:00 y 18:00
    },
    "temporal": {
        "max_queries": 1,  # Máximo 1 consulta
        "token_duration": 1 * 60,  # 1 hora en minutos
        "access_schedule": None,  # Sin restricción de horarios
    },
}
