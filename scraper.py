"""
title: aXL - scraper
description: Scrapes web page for domains
author: arapurayil
License: GPLv3
"""
from datetime import datetime
from pathlib import Path

from bs4 import BeautifulSoup

from generator import get_response, is_path, DirPath


def get_link(url):
    """
    Scrape links from content from the link
    """
    soup = BeautifulSoup(get_response(url).content, "html.parser")
    return [link.get("href") for link in soup.find_all("a")]


def main():
    """
    Main function
    """
    url_oisd = "https://oisd.nl/excludes.php"
    excludes_oisd = get_link(url_oisd)
    excludes_oisd = [x.replace("?w=", "") for x in excludes_oisd if x is not None]
    file_oisd = is_path(Path.joinpath(DirPath.core, "oisd_excluded.txt"))
    header = (
        "# The oisd list excludes (some of) the domains that "
        "exist on the full agreggated list."
        "\n# All the domains excluded are listed below."
        "\n# Maintainer: sjhgvr"
        "\n# url: https://oisd.nl/excludes.php"
        "\n# Last modified: " + datetime.now().strftime("%d %b %Y %H:%M:%S UTC") + "\n"
    )

    with open(file_oisd, "w", encoding="utf-8") as file:
        file.write(header)
        file.write("\n".join(excludes_oisd))


if __name__ == "__main__":
    main()
