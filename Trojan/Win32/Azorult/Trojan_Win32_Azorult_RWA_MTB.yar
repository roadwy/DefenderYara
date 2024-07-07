
rule Trojan_Win32_Azorult_RWA_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 ec 98 09 00 00 83 3d 90 01 04 37 0f 90 02 05 33 c0 89 45 90 01 01 89 45 90 01 01 89 45 90 01 01 89 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RWA_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 ec 1c 04 00 00 a1 90 01 04 33 c4 89 84 24 90 01 04 a1 90 01 04 56 57 8b 3d 90 01 04 a3 90 01 04 33 f6 eb 90 00 } //1
		$a_03_1 = {81 fe cc 6b 84 00 75 90 01 01 b8 31 a2 00 00 01 05 90 01 04 46 81 fe c5 0a 26 01 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}