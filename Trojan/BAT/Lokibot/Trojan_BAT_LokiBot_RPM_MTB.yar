
rule Trojan_BAT_LokiBot_RPM_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 1b 59 1c 58 0d 09 17 fe 04 13 09 11 09 2d c3 06 17 58 0a 00 08 1a 59 1b 58 0c 08 20 00 c6 00 00 fe 04 13 0a 11 0a 2d a5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_LokiBot_RPM_MTB_2{
	meta:
		description = "Trojan:BAT/LokiBot.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 00 11 04 17 58 13 04 11 04 17 fe 04 13 05 11 05 2d c0 06 17 58 0a 00 09 17 58 0d 09 20 00 24 01 00 fe 04 13 06 11 06 2d a3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_LokiBot_RPM_MTB_3{
	meta:
		description = "Trojan:BAT/LokiBot.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 70 00 6c 00 2f 00 76 00 69 00 65 00 77 00 2f 00 72 00 61 00 77 00 2f 00 39 00 39 00 37 00 39 00 30 00 36 00 66 00 66 00 } //1 pastebin.pl/view/raw/997906ff
		$a_01_1 = {47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 GetString
		$a_01_2 = {45 00 78 00 65 00 63 00 75 00 74 00 65 00 52 00 65 00 61 00 64 00 65 00 72 00 } //1 ExecuteReader
		$a_01_3 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 00 20 00 28 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 31 00 30 00 2e 00 30 00 } //1 Mozilla/5.0 (Windows NT 10.0
		$a_01_4 = {4c 61 74 65 47 65 74 } //1 LateGet
		$a_01_5 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_01_6 = {67 65 74 5f 54 69 63 6b 73 } //1 get_Ticks
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}