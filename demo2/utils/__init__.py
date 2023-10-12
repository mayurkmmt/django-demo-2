import calendar, uuid, re
from django.conf import settings
import tldextract


def get_month_day_range(date):
    """
    For a date 'date' returns the start and end date for the month of 'date'.

    Month with 31 days:
    >>> date = datetime.date(2011, 7, 27)
    >>> get_month_day_range(date)
    (datetime.date(2011, 7, 1), datetime.date(2011, 7, 31))

    Month with 28 days:
    >>> date = datetime.date(2011, 2, 15)
    >>> get_month_day_range(date)
    (datetime.date(2011, 2, 1), datetime.date(2011, 2, 28))
    """
    first_day = date.replace(day=1)
    last_day = date.replace(day=calendar.monthrange(date.year, date.month)[1])
    return first_day, last_day


def safeint(val):
    try:
        return int(val)
    except Exception:
        return 0


def check_zone_domain(value):
    ext = tldextract.extract(value)
    if ".".join([ext.domain, ext.suffix]) == "yk1.net":
        return True
    return False
