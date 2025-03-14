import argparse
import sys
import os

TMP_PATH = "./tmp"

DIFFICULTY_TO_CODE_FILE = {
    0: "code_easy.py",
    1: "code_medium.py",
    2: "",
}


def generate_flag(group_name, difficulty) -> str:
    return abs(hash(group_name + str(difficulty))) % 10**9


def generate_pcap(group_name, difficulty, flag) -> str:
    """
    Generate pcap file using params, saves to TMP_PATH with returned file name
    """
    pass


def generate_zip(output_path, group_name, difficulty):
    flag = generate_flag(group_name, difficulty)
    pcap_filename = generate_pcap(group_name, difficulty, flag)
    code_filename = DIFFICULTY_TO_CODE_FILE[difficulty]
    os.system(f"zip {output_path} {pcap_filename} {code_filename}")
    print(f"Generated zip file at {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate zip file")
    parser.add_argument("output", help="Output file", type=argparse.FileType("w"))
    parser.add_argument("group_name", help="Group name", type=str)
    parser.add_argument("difficulty", help="Difficulty", type=int)
    args = parser.parse_args()
    generate_zip(args.output, args.group_name, args.difficulty)
