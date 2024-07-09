
rule Trojan_BAT_Bladabindi_AADS_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.AADS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {26 11 05 8d ?? 00 00 01 0d 07 09 16 11 05 6f ?? 00 00 0a 26 16 13 06 2b 11 09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 13 06 11 06 09 8e 69 32 e8 } //4
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 31 00 2e 00 65 00 78 00 65 00 } //1 WindowsFormsApp1.exe
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}