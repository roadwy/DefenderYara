
rule TrojanProxy_Win32_Bobax_A{
	meta:
		description = "TrojanProxy:Win32/Bobax.A,SIGNATURE_TYPE_PEHSTR,22 00 20 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {73 65 72 76 69 63 65 20 70 61 63 6b 20 32 } //0a 00  service pack 2
		$a_01_1 = {5c 64 72 69 76 65 72 73 5c 74 63 70 69 70 2e 73 79 73 } //0a 00  \drivers\tcpip.sys
		$a_01_2 = {4e 54 34 00 2e 4e 45 54 00 00 00 00 20 44 61 74 61 43 65 6e 74 65 72 53 72 76 00 00 20 41 64 76 53 72 76 00 20 45 6e 74 53 72 76 00 20 57 65 62 53 72 76 } //01 00 
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 69 70 32 6c 6f 63 61 74 69 6f 6e 2e 62 69 7a 2f } //01 00  http://www.ip2location.biz/
		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 67 72 6f 6b 73 74 65 72 2e 63 6f 6d 2f } //01 00  http://www.grokster.com/
		$a_01_5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 65 64 70 73 63 69 65 6e 63 65 73 2e 6f 72 67 2f 68 74 62 69 6e 2f 69 70 61 64 64 72 65 73 73 } //01 00  http://www.edpsciences.org/htbin/ipaddress
		$a_01_6 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 79 69 70 61 64 64 72 65 73 73 2e 63 6f 6d 2f } //01 00  http://www.myipaddress.com/
		$a_01_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 77 68 61 74 69 73 6d 79 69 70 2e 63 6f 6d 2f } //01 00  http://www.whatismyip.com/
		$a_01_8 = {68 74 74 70 3a 2f 2f 77 77 77 2e 69 70 63 68 69 63 6b 65 6e 2e 63 6f 6d 2f } //00 00  http://www.ipchicken.com/
	condition:
		any of ($a_*)
 
}