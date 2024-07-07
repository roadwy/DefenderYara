
rule Trojan_Win32_Amadey_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Amadey.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 44 24 14 8b 44 24 28 01 44 24 14 8b 4c 24 14 8b 44 24 10 33 cb 33 c1 2b f8 8d 44 24 18 } //1
		$a_01_1 = {8b c7 c1 e8 05 03 44 24 20 03 cd 33 c1 8d 0c 3b 33 c1 2b f0 8b d6 c1 e2 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}