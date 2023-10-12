import logging

logger = logging.getLogger(__name__)

from rest_framework.response import Response
from rest_framework.views import exception_handler

from demo2.exceptions import QuotaReachedException
from demo2.rest.serializers import GatewayResponseSerializer
from kgateway.exceptions import GatewayConnectionException, GatewayValidationException


def handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)

    if isinstance(exc, GatewayConnectionException) or isinstance(
        exc, QuotaReachedException
    ):
        logger.error(
            "error_code: %s, status: %s, message: %s",
            (exc.error_code, exc.status_code, exc.message),
        )
        return Response(
            {"detail": exc.message, "error_code": exc.error_code},
            status=exc.status_code,
        )
    elif isinstance(exc, GatewayValidationException):
        response_serializer = GatewayResponseSerializer(exc.context)
        logger.error(
            "error_code: %s, status: %s, data: %s",
            (exc.error_code, exc.status_code, response_serializer.data),
        )
        return Response(
            {
                "detail": response_serializer.data["message"],
                "field_errors": response_serializer.data["fields"],
                "error_code": exc.error_code,
            },
            status=exc.status_code,
        )

    return response
