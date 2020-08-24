import os
import logging.config

WORK_DIR = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))
))
TEMP_DIR = os.path.join(WORK_DIR, ".tmp")
CONFIG_DIR = os.path.join(WORK_DIR, "config")

if not os.path.exists(CONFIG_DIR):
    os.mkdir(CONFIG_DIR)

DEFAULT_COUNTRY_NAME = "US"
DEFAULT_STATE_OR_PROVINCE_NAME = "Texas"
DEFAULT_LOCALITY_NAME = "Austin"
DEFAULT_ORGANIZATION_NAME = "My Test Company"
DEFAULT_COMMON_NAME = "My Test CA"

DEFAULT_ROOT_CERT_NAME = "rootCA.crt"
DEFAULT_ROOT_KEY_NAME = "rootCA.key"

DEFAULT_EXPIRY_DATE = 90  # The maximum validity period of TLS/SSL certificates is currently at 825 days (2 years, 3 month, and 5 days).
logger_config = {
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
logging.config.dictConfig(logger_config)
