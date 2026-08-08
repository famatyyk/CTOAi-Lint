def bad_cpp():
    buf = ""
    strcpy(buf, "x")   # noqa
    sprintf(buf, "%s", "y")
