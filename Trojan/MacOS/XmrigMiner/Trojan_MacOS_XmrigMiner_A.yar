
rule Trojan_MacOS_XmrigMiner_A{
	meta:
		description = "Trojan:MacOS/XmrigMiner.A,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {2e 00 2f 00 78 00 6d 00 72 00 69 00 67 00 } //3 ./xmrig
		$a_00_1 = {2d 00 6f 00 20 00 73 00 74 00 72 00 61 00 74 00 75 00 6d 00 2b 00 74 00 63 00 70 00 3a 00 2f 00 2f 00 } //5 -o stratum+tcp://
		$a_00_2 = {2d 00 6f 00 20 00 73 00 74 00 72 00 61 00 74 00 75 00 6d 00 2b 00 75 00 64 00 70 00 3a 00 2f 00 2f 00 } //5 -o stratum+udp://
		$a_00_3 = {2d 00 63 00 20 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 6a 00 73 00 6f 00 6e 00 } //2 -c config.json
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*2) >=5
 
}