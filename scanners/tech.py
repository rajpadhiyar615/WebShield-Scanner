import builtwith

def detect_technology(url):
    try:
        tech = builtwith.parse(url)

        if not tech:
            return {"Technology": "No technologies detected"}

        return tech

    except Exception as e:
        return {"Error": str(e)}