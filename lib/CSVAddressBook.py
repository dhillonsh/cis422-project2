"""
Handle CSV creating and parsing for an address book.
"""
#pylint: disable=W0312
import io
import csv

class CSVAddressBook(object):
    """
    Create and parse CSV objects given a list of fields and a list of entries.

    """

    @staticmethod
    def create_csv_object(fields, entries):
        """Using a list of fields and entries, return a csv object.

        """
        fields.sort()

        string_io = io.StringIO()

        csv_writer = csv.writer(string_io, delimiter='\t')
        csv_writer.writerow(fields)

        for entry in entries:
            csv_writer.writerow([entry[field] for field in fields])

        return string_io

    @staticmethod
    def parse_csv_string(csv_string):
        """Parse a csv string.

        Args:
            csv_string (str): The string representation of a csv object of fiels and entries.

        Returns:
            A tuple of (address_book_fields, address_book_entries) if the address_hash was valid,
            else (None, None)
        """
        try:
            csv_reader = csv.reader(csv_string.splitlines(), delimiter='\t')

            if not csv_reader:
                return ([], [])

            fields = next(csv_reader)
            entries = []

            for entry in csv_reader:
                field_obj = {}
                for field_index, field in enumerate(fields):
                    field_obj[field] = entry[field_index]

                entries.append(field_obj)

        except:
            return (None, None)

        return (fields, entries)

