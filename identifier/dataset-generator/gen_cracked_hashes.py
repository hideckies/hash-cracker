import codecs
import concurrent.futures
import gen_dataset as gd
import sys

MAX_WORDS_RANGES = 500000


def proc(hash, w):
    try:
        func = getattr(gd, f'data_{hash}')
        data = func(w)
        return [data[0], data[1], w]
    except:
        print(f"{w}: The hash not generated.")
        return []


def main():
    if (len(sys.argv) != 3):
        print(f"Specify the target hash and the range of the words.\n")
        print("Example:")
        print("python3 gen_cracked_hashes.py md5 0-20000")
        return

    hash = sys.argv[1]
    rng = sys.argv[2]
    print(f"Target hash is {hash}")
    print(f"The words range is {rng}")

    # Test 
    if hasattr(gd, f'data_{hash}'):
        print(f"\"data_{hash}\" function exists. Proceed...")
    else:
        print(f"\"data_{hash}\" function does not exist. Specify the correct hash name.")
        return

    datas = []

    with codecs.open('/usr/share/wordlists/rockyou.txt', 'r', encoding='utf-8', errors='ignore') as f:
        words = [w.rstrip() for w in f.readlines()]

    print(f"Max words length is {len(words)}.")

    # Extract the words
    rngs = [int(e) for e in rng.split("-", 2)]
    if len(rngs) == 1:
        rngs.append(rngs[0] + int(MAX_WORDS_RANGES / 2))
    if rngs[1] > len(words):
        rngs[1] = len(words)
    if (rngs[1] - rngs[0]) <= 0:
        print("The range is incorrect.")
        return
    if (rngs[1] - rngs[0]) > MAX_WORDS_RANGES:
        print("The range too large. (max lange is )")
        return
    print(f"Start generating {hash} hashes using words[{rngs[0]}:{rngs[1]}] .")
    s = slice(rngs[0], rngs[1])
    words = words[s]
    print(f"words length is {len(words)}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        futures = [executor.submit(proc, hash, word) for word in words]
        print(f"Executing total {len(futures)} jobs")
        for future in concurrent.futures.as_completed(futures):
            datas.append(future.result())

    print("hashes generated completely.")
    # Add to the database.
    print("Add hashes to the database...")


if __name__ == "__main__":
    main()