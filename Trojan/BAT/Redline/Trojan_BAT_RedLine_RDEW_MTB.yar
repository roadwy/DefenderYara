
rule Trojan_BAT_RedLine_RDEW_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 68 6e 4c 61 62 20 56 33 20 4c 69 74 65 } //1 AhnLab V3 Lite
		$a_01_1 = {47 65 74 44 69 73 70 61 74 63 68 65 72 } //1 GetDispatcher
		$a_01_2 = {43 6f 6e 6e 65 63 74 44 69 73 70 61 74 63 68 65 72 } //2 ConnectDispatcher
		$a_01_3 = {53 65 61 72 63 68 44 69 73 70 61 74 63 68 65 72 } //2 SearchDispatcher
		$a_01_4 = {51 75 65 72 79 44 69 73 70 61 74 63 68 65 72 } //2 QueryDispatcher
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=8
 
}