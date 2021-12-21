suricata:
	git clone https://github.com/OISF/suricata.git
	cd suricata && git clone https://github.com/OISF/libhtp && ./autogen.sh && ./configure
	cd suricata && ./scripts/setup-app-layer.py --parser MephiParser
	cp -r ./../../module/src/ ./suricata/
	cp -r ./../../module/rules/ ./suricata/
