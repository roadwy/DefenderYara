
rule Trojan_Win32_DLLLoader_EC_MTB{
	meta:
		description = "Trojan:Win32/DLLLoader.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4c b2 04 33 0c b2 23 cb 33 0c b2 8b c1 d1 e9 83 e0 01 33 0c 85 90 01 04 33 8c b2 90 01 04 89 0c b2 46 81 fe e3 00 00 00 7c d3 90 00 } //7
		$a_01_1 = {71 62 6f 74 34 5c 64 6c 6c 5f 64 72 6f 70 70 65 72 } //1 qbot4\dll_dropper
	condition:
		((#a_03_0  & 1)*7+(#a_01_1  & 1)*1) >=8
 
}