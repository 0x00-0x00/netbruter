def format_time(t):
    if t > 86400:
        days = (t / 86400)
        hours = (t % 86400) / 3600
        minutes = (t % 3600) / 60
        seconds = ((t % 86400) % 3600) % 60
        return "%2.fd %2.fh %2.fm %2.fs" % (days, hours, minutes, seconds)
    elif t > 3600:
        hours = (t / 3600.0)
        minutes = ((t % 3600) / 60)
        seconds = ((t % 3600) % 60)
        return "%2.fh %2.fm %2.fs" % (hours, minutes, seconds)
    elif t > 60:
        minutes = (t / 60)
        seconds = (t % 60)
        return "%2.fm %2.fs" % (minutes, seconds)
    else:
        seconds = t
        return "%2.fs" % seconds
