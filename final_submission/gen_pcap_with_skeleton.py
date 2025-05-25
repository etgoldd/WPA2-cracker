import argparse
import sys
import os
from typing import Optional
from gen import gen_pcaps

SCRAMBLE_MIC = [0, 0, 0, 1, 1, 1]
SKELETON_FILE = ["skeletons/skeleton_easy.py", "skeletons/skeleton_medium.py", "skeletons/skeleton_hard.py",
                 "skeletons/skeleton_easy.py", "skeletons/skeleton_medium.py", "skeletons/skeleton_hard.py"]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate zip file")
    parser.add_argument("output", help="Output file", type=str)
    parser.add_argument("group_name", help="Group name", type=str)
    parser.add_argument("difficulty", help="Difficulty", type=int)
    parser.add_argument("-f", "--flag", help="override automatic generation of the flag", type = str)
    args = parser.parse_args()
    if args.difficulty < 0 or args.difficulty >= 6:
        print("difficulty out of range, we support 0-5 (inclusive), 0 is easiest, 5 is hardest")
    
    file_hint = None

    with open(SKELETON_FILE[args.difficulty], "r") as file:
        file_hint = file.read()
    print(str(args.output))
    gen_pcaps(args.group_name, PCAP_LOC=str(args.output), flag=args.flag, faulty_mic=SCRAMBLE_MIC[args.difficulty], solution_file_hint=file_hint)