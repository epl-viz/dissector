# This is now part of Wireshark 2.4.0

Changes to the original EPL-Dissector done here have been merged into Wireshark 2.4.0 released on 2017-07-19.
This repository is out of date and is only kept for historical (i.e. git-log) purposes. Base your work off `wireshark/epan/dissectors/packet-epl.c` instead.

See https://code.wireshark.org/review/#/c/21112/ for the code review and subsequent patches to the code here.

----


## EPL-Dissector with XDD support plugin for Wireshark

Parses XDD/EDS files and uses extracted information to correctly label SDOs and PDOs. Depends on libxml2. Tested working with Wireshark v2.2.4.

#### Don't clone this

    git clone --recursive https://github.com/epl-viz/wireshark

instead. Build files for plugins expect to be ran out the wireshark source tree.

### Installation

As the stock EPL dissector is already linked when the plugin DLL is loaded, one needs to manually disable it (`Analyze ❯ Enabled Protocols`). When using libwireshark, one could call `proto_disable_proto_by_name("epl")` before commencing dissection. To keep the dissectors apart, this one is called EPL+XDD with `epl-xdd` as Wireshark protocol abbreviation.

### Acknowledgement

Special thanks to Peter Wu (Lekensteyn).

### License

The base dissector and any modification are licensed under the GNU GPL2.0+.

