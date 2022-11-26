import js2py


def load_determine_basal(fp):
    with open(fp, "r", encoding="utf-8") as fo:
        return js2py.eval_js(fo.read())


def run_determine_basal(determine_basal, **params):
    return determine_basal(**params)
