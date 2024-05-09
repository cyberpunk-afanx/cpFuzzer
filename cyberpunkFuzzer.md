### Into

This fuzzer is for testing the program in specific places and is a testing wrapper.

To be able to use it, you need to have experience with pwntool.

Write the path to the location of interest between the comments `### start here` and `### stop here`.

It looks like a normal CTF exploit of the PWN category, so there should be no problems.

### Install

Install pwntool:

```
$ apt-get update
$ apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
$ python3 -m pip install --upgrade pip
$ python3 -m pip install --upgrade pwntools
```

### Usage

```
python3 cpfuzzer.py <binary> > fuzzer.py
```

On successful fuzzing, the crash will be saved to a file in the current directory with the crash name and crash length, and the contents will be crash data.