
rule TrojanProxy_Win32_Banker_AP{
	meta:
		description = "TrojanProxy:Win32/Banker.AP,SIGNATURE_TYPE_PEHSTR_EXT,70 00 70 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00 } //01 00  \drivers\etc\hosts
		$a_01_1 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //01 00  \drivers\etc\hosts
		$a_01_2 = {61 00 74 00 74 00 72 00 69 00 62 00 20 00 2d 00 72 00 } //01 00  attrib -r
		$a_01_3 = {61 74 74 72 69 62 20 2d 72 } //64 00  attrib -r
		$a_01_4 = {63 72 65 61 72 5f 62 61 74 } //0a 00  crear_bat
		$a_01_5 = {76 69 61 62 63 70 2e 63 6f 6d 0d 0a } //0a 00 
		$a_01_6 = {69 6e 74 65 72 62 61 6e 6b 2e 63 6f 6d 2e 70 65 0d 0a } //0a 00 
		$a_01_7 = {62 6e 2e 63 6f 6d 2e 70 65 0d 0a } //00 00 
	condition:
		any of ($a_*)
 
}