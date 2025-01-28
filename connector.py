"""
Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""

from connectors.core.connector import Connector, ConnectorError, get_logger
from .operations import operations, _check_health

logger = get_logger('anyrun')


class anyrun(Connector):
    def execute(self, config, operation_name, params, **kwargs):
        try:
            logger.info(f"Executing operation: {operation_name}")
            op = operations.get(operation_name)
            if not op:
                raise ConnectorError(f"Operation '{operation_name}' is not defined.")
            
            # Execute the operation with config and params
            result = op(config, params)
            logger.info(f"Operation '{operation_name}' completed successfully.")
            return result
        
        except ConnectorError as e:
            logger.error(f"ConnectorError during '{operation_name}': {e}")
            raise
        
        except Exception as e:
            logger.exception(f"An unexpected error occurred during '{operation_name}': {e}")
            raise ConnectorError(e)

    def check_health(self, config):
        try:
            # Perform a health check using the function defined in operations.py
            health_status = _check_health(config)
            logger.info("Health check completed successfully.")
            return health_status

        except ConnectorError as e:
            logger.error(f"Health check failed with ConnectorError: {e}")
            raise
        
        except Exception as e:
            logger.error(f"An unexpected error occurred during health check: {e}")
            raise ConnectorError(e)
