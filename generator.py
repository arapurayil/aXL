"""
title: aXL - generator
description: Generates lists of excluded domains and unblock rules for aBL.
author: arapurayil
credits: https://github.com/AdguardTeam/HostlistCompiler
license: GPLv3
"""
import subprocess
from collections import namedtuple

from dataclasses import dataclass
from datetime import datetime
from glob import glob
from itertools import chain

from json import load, loads, dump
from pathlib import Path
from textwrap import fill

from regex import regex as re
from requests import Session
from requests.adapters import HTTPAdapter, Retry
from tqdm import tqdm
from validators import domain as valid_domain

import markdown_strings


def is_path(path):
    """Creates file/directory if path doesn't exist and/or returns path."""
    if Path(path).suffix:
        if not Path(path).exists():
            if not Path(path).parents[0].exists():
                Path(path).parents[0].mkdir(parents=True, exist_ok=True)
            Path(path).open("x", encoding="utf-8").close()
        return Path(path)
    if not Path(path).exists():
        Path(path).mkdir(parents=True, exist_ok=True)
    return Path(path)


def read_file(path, data_type="list"):
    """Reads a file and returns its contents."""
    if Path(path).suffix == ".json":
        with open(path, encoding="utf-8") as file:
            return load(file)
    else:
        with open(path, encoding="utf-8") as file:
            return file.readlines() if data_type == "list" else file.read()


def write_file(data, path):
    """Writes a file with the given data."""
    if Path(path).suffix == ".json":
        if isinstance(data, str):
            data = loads(data)
        with open(path, "w", encoding="utf-8") as file:
            file.seek(0)
            dump(data, file, indent=4)
            file.truncate()
    else:
        with open(path, "w", encoding="utf-8") as output_file:
            for line in data:
                output_file.write(line)


@dataclass
class DirPath:
    """For the source json file."""

    base = Path(__file__).parents[0]
    core = is_path(Path.joinpath(base, "core"))
    source = is_path(Path.joinpath(base, "sources"))
    hc_config = is_path(Path.joinpath(base, "config"))
    output_list = is_path(Path.joinpath(base, "lists"))


@dataclass
class JsonKey:
    """Keys for the source json file."""

    def __init__(self, **kwargs):
        self.desc = None
        self.title = None
        self.__dict__.update(kwargs)


@dataclass
class ItemKey:
    """Keys for the individual source items in the source json file"""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


@dataclass
class ListInfo:
    """Values for the list header."""

    title = "arapurayil's eXcluded List - aXL"
    author = "arapurayil"
    version = (
        str(int(datetime.now().strftime("%Y")) - 2019)
        + "."
        + datetime.now().strftime("%m")
        + "."
        + datetime.now().strftime("%d")
    )
    last_modified = datetime.now().strftime("%d %b %Y %H:%M:%S UTC")
    expires = "8 hours"
    repo = "https://github.com/arapurayil/aBL"
    home = "https://axl.arapurayil.com"

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


@dataclass
class ListGenerator:
    """The main class."""

    j_key = JsonKey(
        title="title",
        desc="description",
        sources="sources",
    )
    i_key = ItemKey(
        name="name",
        url="url",
        desc="desc",
        format="format",
        type="type",
        num_block_rules="num_block_rules",
        num_unblock_rules="num_unblock_rules",
    )
    info = ListInfo(
        header=(
            f"repl_cmt Title: repl_cat_title\n"
            f"repl_cmt Author: {ListInfo.author}\n"
            f"repl_cmt Description: repl_cat_desc\n"
            f"repl_cmt Version: {ListInfo.version}\n"
            f"repl_cmt Last modified: {ListInfo.last_modified}\n"
            f"repl_cmt Expires: {ListInfo.expires} (update frequency)\n"
            f"repl_cmt Home: {ListInfo.home}\n"
            f"repl_cmt Repository: {ListInfo.repo}\n"
            f"repl_cmt Issues: {ListInfo.repo}/issues\n"
            f"repl_cmt Please report the domains you wish to block/unblock via 'Issues'\n"
            f"repl_cmt Licence: {ListInfo.repo}/license\n"
            f"repl_cmt-----------------------------------------"
            f"---------------------------------------------repl_cmt\n"
        ),
    )

    def __init__(self, file_json, **kwargs):
        self.file_json = file_json
        self.category = Path(file_json).stem
        self.data_json = read_file(file_json)
        self.dir_output_filters = DirPath.output_list
        self.dir_cat = Path.joinpath(DirPath.source, Path(file_json).stem)
        self.__dict__.update(kwargs)


def extract_hosts(content, list_type):
    """Extracts blocked or unblocked domains from hosts/domains style content."""
    pattern_scrub = [
        r"(?>\#|\!|\s+\#|\s+\!).*",
        r"^\s",
        r"^\.",
        r".*\blocalhost\b.*",
        r"^\d*\.\d*\.\d*\.\d*\s*(?>\s|www\.|m\.)",
        r"^(?>www\.|m\.)",
    ]
    pattern = re.compile("|".join(f"(?:{p})" for p in pattern_scrub), re.V1)
    domains = [re.sub(pattern, "", x, concurrent=True) for x in content]
    domains = [x for x in domains if valid_domain(x)]
    blocked_domains, unblocked_domains = [], []
    if list_type == "unblock":
        unblocked_domains = domains
    if list_type == "block":
        blocked_domains = domains

    return blocked_domains, unblocked_domains


def extract_abp(content):
    """Extracts blocked and unblocked domains from ABP style content."""
    pattern_unsupported = re.compile(r"\S+(?>\/|\=)\S+", re.V1)
    pattern_supported_unblock = re.compile(r"@@\|\|.+\^$")
    return [
        x
        for x in content
        if re.match(pattern_supported_unblock, x, concurrent=True)
        and not re.match(pattern_unsupported, x, concurrent=True)
    ]


def get_response(url):
    """Fetches response headers for the URL."""
    retries = Retry(
        total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504]
    )
    http = Session()
    http.mount("https://", HTTPAdapter(max_retries=retries))
    http.headers.update(
        {
            "Connection": "keep-alive",
            "User-Agent": "Mozilla/5.0 (Linux x86_64; rv:75.0) Gecko/20100101 Firefox/75.0",
        }
    )

    return http.get(url, allow_redirects=True, timeout=30)


def get_content(url):
    """Fetches content for the URL."""
    return get_response(url).content.decode("utf-8")


def worker_process_sources(item, blg):
    """Worker for process_sources via ThreadPoolExecutor."""
    unprocessed = get_content(item[blg.i_key.url]).splitlines()
    blocked_domains, unblocked_domains = (
        [],
        [],
    )

    if item[blg.i_key.format] == "domains":
        blocked_domains, unblocked_domains = extract_hosts(
            unprocessed, item[blg.i_key.type]
        )

    item[blg.i_key.num_block_rules] = len(blocked_domains)
    item[blg.i_key.num_unblock_rules] = len(unblocked_domains)
    write_file(blg.data_json, blg.file_json)
    return blocked_domains, unblocked_domains


def process_sources(blg):
    """Processes the source json file for the category
    Fetches the content for the url for each individual source and,
    extracts blocked and unblocked domains from it and,
    appends it the unified blocked and unblocked domains for the category.
    """
    blg.data_json[blg.j_key.sources] = sorted(
        blg.data_json[blg.j_key.sources], key=lambda x: x[blg.i_key.name].upper()
    )
    blocked_domains, unblocked_domains = (
        [],
        [],
    )

    blocked_d, unblocked_d = [], []
    for item in blg.data_json[blg.j_key.sources]:
        unprocessed = get_content(item[blg.i_key.url]).splitlines()
        if item[blg.i_key.format] == "domains":
            blocked_d, unblocked_d = extract_hosts(unprocessed, item[blg.i_key.type])
            blocked_domains.append(blocked_d)
            unblocked_domains.append(unblocked_d)

        item[blg.i_key.num_block_rules] = len(blocked_d)
        item[blg.i_key.num_unblock_rules] = len(unblocked_d)
        write_file(blg.data_json, blg.file_json)

    blocked_domains = chain.from_iterable(blocked_domains)
    unblocked_domains = chain.from_iterable(unblocked_domains)

    return blocked_domains, unblocked_domains


def write_version(blg):
    """Writes version number to a file."""
    file_version = Path.joinpath(DirPath.base, "version.txt")
    write_file(blg.info.version, file_version)


def gen_filter_list(blg, unblocked_domains):
    """
    Generate filter list
    """
    file_filter = is_path(Path.joinpath(blg.dir_output_filters, f"{blg.category}.txt"))
    unblocked_domains = sorted(unblocked_domains)
    list_title = f"{blg.info.title} - {blg.data_json[blg.j_key.title]}"
    header = (
        str(blg.info.header)
        .replace("repl_cat_title", list_title)
        .replace("repl_cat_desc", blg.data_json[blg.j_key.desc])
    )
    _num_processed = 0
    _num_processed += len(unblocked_domains)

    unblocked_domains = "\n".join(unblocked_domains) + "\n"

    with open(file_filter, "w", encoding="utf-8") as file:
        file.write(header.replace("repl_cmt", "#"))
        if unblocked_domains:
            for line in unblocked_domains:
                file.write(line)

    write_version(blg)
    return _num_processed


def category_section_main(blg):
    """Generates the main section of the category README.md file."""
    link_filter = markdown_strings.link(
        "Download",
        f"{blg.info.home}/lists/{blg.category}.txt",
    )
    main_title = (
        markdown_strings.header(f"{blg.data_json[blg.j_key.title]}", 1)
        + "\n"
        + "**"
        + link_filter
        + "**"
    )

    main_desc = markdown_strings.bold(f"{fill(blg.data_json[blg.j_key.desc])}")

    return [main_title, main_desc]


def category_section_table(blg):
    """Generates the table for the category README.md file."""
    tbl_col_tup = namedtuple("tbl_col_tup", "c1, c2, c3, c4, c5")
    tbl_col_arr = [
        "#",
        "Title",
        "Description",
        "Unblocked domains",
        "Re-blocked domains",
    ]
    tbl_col = tbl_col_tup(*tbl_col_arr)
    tbl_pad_arr = [
        len("---"),
        len(tbl_col.c2),
        len(tbl_col.c3),
        len(tbl_col.c4),
        len(tbl_col.c5),
    ]
    tbl_pad = tbl_col_tup(*tbl_pad_arr)
    for index, key in enumerate(blg.data_json[blg.j_key.sources]):
        if len(str({index + 1}).zfill(2)) > tbl_pad.c1:
            tbl_pad_arr[0] = len(str({index + 1}).zfill(2)) + 2
        if len(str(f"[{key[blg.i_key.name]}]({key[blg.i_key.url]})")) > tbl_pad.c2:
            tbl_pad_arr[1] = (
                len(str(f"[{key[blg.i_key.name]}]({key[blg.i_key.url]})")) + 2
            )
        if len(str({key[blg.i_key.desc]})) > tbl_pad.c3:
            tbl_pad_arr[2] = len(str({key[blg.i_key.desc]})) + 2
        if len(str({key[blg.i_key.num_unblock_rules]})) > tbl_pad.c4:
            tbl_pad_arr[3] = len(str({key[blg.i_key.num_unblock_rules]})) + 2
        if len(str({key[blg.i_key.num_block_rules]})) > tbl_pad.c5:
            tbl_pad_arr[4] = len(str({key[blg.i_key.num_block_rules]})) + 2
        tbl_pad = tbl_col_tup(*tbl_pad_arr)
    table_title_row = markdown_strings.table_row(
        [tbl_col.c1, tbl_col.c2, tbl_col.c3, tbl_col.c4, tbl_col.c5],
        [tbl_pad.c1, tbl_pad.c2, tbl_pad.c3, tbl_pad.c4, tbl_pad.c5],
    )
    table_delimiter = markdown_strings.table_delimiter_row(
        5,
        column_lengths=[tbl_pad.c1, tbl_pad.c2, tbl_pad.c3, tbl_pad.c4, tbl_pad.c5],
    )
    table_contents = []
    for index, key in enumerate(blg.data_json[blg.j_key.sources]):
        link = markdown_strings.link(key[blg.i_key.name], key[blg.i_key.url])
        row = markdown_strings.table_row(
            [
                str(index + 1).zfill(2),
                link,
                key[blg.i_key.desc],
                key[blg.i_key.num_unblock_rules],
                key[blg.i_key.num_block_rules],
            ],
            [tbl_pad.c1, tbl_pad.c2, tbl_pad.c3, tbl_pad.c4, tbl_pad.c5],
        )
        table_contents.append(row)
    return [table_title_row, table_delimiter, "\n".join(table_contents)]


def gen_category(blg):
    """Generates README.md for the blocklist category."""
    section = [
        "\n\n".join(category_section_main(blg)),
        "\n".join(category_section_table(blg)),
    ]
    data_md = "\n\n".join(section) + "\n\n"

    file_category = is_path(Path.joinpath(blg.dir_cat, "README.md"))
    write_file(data_md, file_category)


def blocklist_section_table(list_sources):
    """The table for the blocklist README.md file."""
    tbl_col_tup = namedtuple("tbl_col_tup", "c1, c2, c3, c4")
    tbl_col_arr = ["#", "TITLE", "DESCRIPTION", "DOWNLOAD LINK"]
    tbl_col = tbl_col_tup(*tbl_col_arr)
    tbl_pad_arr = [
        len("---"),
        len(tbl_col.c2),
        len(tbl_col.c3),
        len(tbl_col.c4),
    ]
    table_contents = []
    tbl_pad = tbl_col_tup(*tbl_pad_arr)
    for index, file in enumerate(list_sources):
        blg = ListGenerator(
            file_json=file,
        )
        filter_list_link = markdown_strings.link(
            f"{blg.info.home}/lists/{blg.category}.txt",
            f"{blg.info.home}/lists/{blg.category}.txt",
        )
        if len(str(index + 1).zfill(2)) > tbl_pad.c1:
            tbl_pad_arr[0] = len(str(index + 1).zfill(2)) + 2
        if len(str(blg.data_json[blg.j_key.title])) > tbl_pad.c2:
            tbl_pad_arr[1] = len(str(blg.data_json[blg.j_key.title])) + 2
        if len(str(blg.data_json[blg.j_key.desc])) > tbl_pad.c3:
            tbl_pad_arr[2] = len(str(blg.data_json[blg.j_key.desc])) + 2
        if len(str(filter_list_link)) > tbl_pad.c4:
            tbl_pad_arr[3] = len(str(filter_list_link)) + 2
        tbl_pad = tbl_col_tup(*tbl_pad_arr)
    for index, file in enumerate(list_sources):
        blg = ListGenerator(
            file_json=file,
        )
        filter_list_link = markdown_strings.link(
            f"{blg.info.home}/lists/{blg.category}.txt",
            f"{blg.info.home}/lists/{blg.category}.txt",
        )
        row = markdown_strings.table_row(
            [
                str(index + 1).zfill(2),
                str(blg.data_json[blg.j_key.title]),
                str(blg.data_json[blg.j_key.desc]),
                str(filter_list_link),
            ],
            [tbl_pad.c1, tbl_pad.c2, tbl_pad.c3, tbl_pad.c4],
        )
        table_contents.append(row)
    table_delimiter = markdown_strings.table_delimiter_row(
        4, column_lengths=[tbl_pad.c1, tbl_pad.c2, tbl_pad.c3, tbl_pad.c4]
    )
    table_title_row = markdown_strings.table_row(
        [tbl_col.c1, tbl_col.c2, tbl_col.c3, tbl_col.c4],
        [tbl_pad.c1, tbl_pad.c2, tbl_pad.c3, tbl_pad.c4],
    )
    return [table_title_row, table_delimiter, "\n".join(table_contents)]


def concat_category(out_file):
    """Concatenate category README.md files"""
    files = glob(f"{DirPath.source}/*/*.md")
    files = sorted(files, key=lambda x: x)
    files = sorted(files, key=lambda x: x.__contains__("main"), reverse=True)
    for file in files:
        with open(file, encoding="utf-8") as file_input:
            with open(out_file, "a", encoding="utf-8") as file_output:
                lines = (
                    re.sub(r"^#", r"##", x) if re.match(r"^#{0,6}+\s", x) else x
                    for x in file_input
                )
                file_output.writelines(lines)


def gen_project_readme(list_source):
    """Generate README.md for aBL from category README.md files."""
    file_badges = is_path(Path.joinpath(DirPath.base, "BADGES.md"))
    file_about = is_path(Path.joinpath(DirPath.base, "ABOUT.md"))
    file_notes = is_path(Path.joinpath(DirPath.base, "NOTE.md"))
    main_title = markdown_strings.header(ListInfo.title, 1)
    badges = read_file(file_badges, data_type="str")
    about = read_file(file_about, data_type="str")
    notes = read_file(file_notes, data_type="str")
    info_add = markdown_strings.blockquote(
        "List of excluded domains and unblock rules. Primarily used for [aBL](https://github.com/arapurayil/abl)."
    )
    section = [
        main_title,
        info_add,
        badges or None,
        about or None,
        "\n".join(blocklist_section_table(list_source)),
        notes or None,
    ]
    data_md = "\n\n".join(filter(None, section)) + "\n\n"
    file_readme = is_path(Path.joinpath(DirPath.base, "README.md"))
    with open(file_readme, "w", encoding="utf-8") as file_output:
        file_output.writelines(data_md)
    concat_category(file_readme)


def run_hostlist_compiler(blg):
    """
    Generate filter list
    """
    file_config = is_path(f"{DirPath.hc_config}/config-{blg.category}.json")
    file_filter = is_path(
        Path.joinpath(blg.dir_output_filters, f"{blg.category}_unblock.txt")
    )
    hc_command = "hostlist-compiler -c " + str(file_config) + " -o " + str(file_filter)
    subprocess.check_call(hc_command, shell=True)


def read_filter(blg):
    file_filter = is_path(Path.joinpath(blg.dir_output_filters, f"{blg.category}.txt"))
    unprocessed = read_file(file_filter)
    unblock = extract_abp(unprocessed)
    unblock = [x.strip() for x in unblock]
    return unblock


def main():
    """
    Main
    """
    list_source = list(glob(f"{DirPath.source}/*.json"))
    list_source = sorted(list_source, key=lambda x: x)
    list_source = sorted(
        list_source, key=lambda x: x.__contains__("main"), reverse=True
    )
    if list_source:
        p_bar = tqdm(list_source, desc="Generating lists")
        list_title = []
        for i, file in enumerate(p_bar):
            li_ge = ListGenerator(
                file_json=file,
            )
            list_title.append(li_ge.data_json[li_ge.j_key.title])
            p_bar.set_description(
                desc=f"Processing sources — {li_ge.data_json[li_ge.j_key.title]}"
            )
            (blocked_domains, unblocked_domains) = process_sources(li_ge)
            blocked_domains = list(blocked_domains)
            unblocked_domains = list(unblocked_domains)
            unblocked_domains = set(unblocked_domains) - set(blocked_domains)
            gen_filter_list(li_ge, unblocked_domains)

            run_hostlist_compiler(li_ge)

            gen_category(li_ge)

            if i == len(list_source) - 1:
                p_bar.set_description(
                    desc=f"Generating README.md for the {li_ge.info.title}"
                )
                gen_project_readme(list_source)
                p_bar.set_description(desc="Done!")
    else:
        print("No sources to process!\nAdd json files to 'sources' directory.")


if __name__ == "__main__":
    main()
