#!/usr/bin/python3
import argparse
import hashlib
import json
import sys


class HashIt(object):

    def __generate_digests(cls, hashers):
        digests = []
        for dig in hashers:
            digests.append(dig.hexdigest())
        return digests

    def __init__(self, rules):
        self.rules = rules

    def __build_hashers(self):
        hashers = []
        for hashengine in self.rules['hashes']:
            he = hashlib.new(hashengine)
            hashers.append(he)
        return hashers

    def __do_hashing(self, hashers, value):
        reader_mod = 0
        start_position = 0
        while start_position < len(value):
            # Find the hasher to use
            reader_index = reader_mod % len(self.rules['reader'])

            # Get the hashing parameters
            he_index, add_value_length = self.rules['reader'][reader_index]

            # Calculate the end of the data
            end_position = start_position + add_value_length

            # Get the data for this hasher
            reader_value = value[start_position:end_position]

            # Add the data to the hasher
            hashers[he_index].update(reader_value)

            # Update the indices
            start_position = end_position + 1
            reader_mod = reader_mod + 1

    def __build_value(self, digests, length):
        results = []
        writer_mod = 0
        start_position = 0
        while start_position < length:
            # Find the hasher to use
            writer_index = writer_mod % len(self.rules['writer'])

            # Get the hashing parameters
            dig_index, add_value_length = self.rules['writer'][writer_index]

            # Calculate the end of the data
            end_position = start_position + add_value_length

            # Get the data for this hasher
            writer_value = digests[dig_index][start_position:end_position]

            # Add the data to the hasher
            results.append(writer_value)

            # Update the indices
            start_position = end_position + 1
            writer_mod = writer_mod + 1

        return ''.join(results)

    def __call__(self, value):
        hashers = self.__build_hashers()
        self.__do_hashing(hashers, value)
        digests = self.__generate_digests(hashers)
        return self.__build_value(digests, len(value))
        

def main():
    arguments = argparse.ArgumentParser(description="Secure Password Storage POC")
    arguments.add_argument(
        '-r', '--rules',
        type=argparse.FileType('r'),
        required=True,
        help="Rules for building the password stored as a JSON document"
    )
    arguments.add_argument(
        '-p', '--password',
        type=argparse.FileType('r'),
        required=True,
        help="User Password Input to be scrambled according to the rules"
    )

    options = arguments.parse_args()

    rules_data = options.rules.read()
    rules = json.loads(rules_data)

    for input_value in options.password:
        encoded_iv = input_value.rstrip('\r\n').encode('utf-8')
        hasher = HashIt(rules)
        output_value = hasher(encoded_iv)

        print('output: {0}'.format(output_value))
        print('individual digests:')
        for he in rules['hashes']:
            engine = hashlib.new(he)
            engine.update(encoded_iv)
            print('\t{0} - {1}'.format(he, engine.hexdigest()))


if __name__ == "__main__":
    sys.exit(main())
