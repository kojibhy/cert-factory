import os

WORK_DIR = os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))
)
CERTIFICATES_DIR = os.path.join(WORK_DIR, "certificates")

LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        "main_frmt": {
            "format": "%(levelname)s:%(name)s: %(message)s(%(asctime)s; %(filename)s:%(lineno)d)",
            "datefmt": "%Y-%m-%d %H:%M:%S"
        }
    },
    'handlers': {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "main_frmt"
        },
    },
    'loggers': {
        'cert_factory': {
            'level': 'DEBUG',
            'handlers': ['console'],
            'propagate': False
        },
    },

}

