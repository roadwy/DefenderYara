
rule Trojan_Win32_Daonol_E{
	meta:
		description = "Trojan:Win32/Daonol.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {89 02 33 f6 c7 44 24 04 2e 2e 5c 00 } //1
		$a_01_1 = {80 f1 d5 88 4c 02 ff 4a 75 f2 } //1
		$a_01_2 = {8a 27 35 d5 d5 00 00 88 66 ff } //1
		$a_01_3 = {76 17 81 bc 24 10 0c 00 00 49 54 53 46 74 0a } //1
		$a_01_4 = {8a 0a 8a 5c 34 0c 32 cb 8d 98 62 0d 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}