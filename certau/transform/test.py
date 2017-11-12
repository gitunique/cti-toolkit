from .text import StixTextTransform
from stix.common import EncodedCDATA
import glob

class StixTestTransform(StixTextTransform):
    """Generate text output of test mechanisms contained within a
    STIX package.

    This class can be used to generate a text dump of the test mechanisms
    associated with indicators contained in a STIX package.

    Args:
        package: the STIX package to process
    """

    def __init__(self, package, default_title=None, default_description=None,
                 default_tlp='AMBER', separator='|', include_header=False,
                 header_prefix='#', include_observable_id=True,
                 include_condition=True):
        super(StixTextTransform, self).__init__(
            package, default_title, default_description, default_tlp,
        )
        self.include_observable_id = include_observable_id
        self.include_condition = include_condition
        self.include_header = include_header
        self.header_prefix = header_prefix

    def header(self):
        title = self.package_title()
        tlp = self.package_tlp()

        if title or tlp:
            header = self.header_prefix
            if title:
                header += ' {}'.format(title)
            if tlp:
                header += ' (TLP:{})'.format(tlp)
            header += '\n'
        else:
            header = ''
        return header

    def text(self):
        """Returns a string representation of the STIX package."""
        text = ''
        for indicator in self.test_mechanisms:
            if (indicator.test_mechanisms is not None): # should never happen
                for tm in indicator.test_mechanisms:
                    if self.include_header:
                        text += '=' * (len(indicator.id_) + 14) + '\n'
                        text += self.header()
                        text += "{:>13} {}".format('Indicator ID:',indicator.id_) + '\n'
                        text += '=' * (len(indicator.id_) + 14) + '\n'

                    for thing in tm.walk():
                        if (isinstance(thing, EncodedCDATA)):
                            text += '{}'.format(thing.value) + '\n'
        return text
