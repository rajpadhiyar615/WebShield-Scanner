# =====================================
# Safe Scanner Wrapper
# =====================================


def safe_scan(function, *args):

    try:

        result = function(*args)

        return result


    except Exception as e:


        return {

            "Error": str(e)

        }