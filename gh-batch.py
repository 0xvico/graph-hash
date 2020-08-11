import os
import subprocess
import argparse

def main():
    i = 0

    if not os.path.isdir('./log'):
        os.mkdir('./log')

    parser = argparse.ArgumentParser()
    parser.add_argument('--ida', help='The path of the text-mode IDA Pro')
    parser.add_argument('--sample', help='The path of samples')
    args = parser.parse_args()

    if args.sample[-1] != '\\':
        args.sample += '\\'

    script = os.getcwd() + '\graph_hash.py batch out_binary'

    samples = os.listdir(args.sample)
    num_sample = len(samples)

    for sample in samples:
        i += 1
        print('%d%%: %s' % (i * 100 / num_sample, sample))
        sample_path = args.sample + sample
        log_path = '.\\log\\' + sample + '.log'
        subprocess.call([args.ida, '-B', '-oout.idb', '-L' + log_path, '-S' + script, sample_path])

    print('DONE!')

if __name__ == '__main__':
    main()
