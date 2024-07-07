
rule Trojan_Win32_Azorult_KMG_MTB{
	meta:
		description = "Trojan:Win32/Azorult.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 0c 16 a1 90 01 04 46 c7 05 90 01 04 d8 53 2a 94 3b f0 72 90 01 01 33 f6 81 fe d8 e0 34 00 75 90 01 01 e8 90 01 04 46 81 fe 74 0f 4d 00 7c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_KMG_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {3d 48 07 00 00 75 90 01 01 89 3d 90 01 04 8b ce e8 90 01 04 a1 90 01 04 46 3b f0 72 90 00 } //1
		$a_00_1 = {b8 e1 bf 01 00 01 04 24 8b 04 24 8a 04 08 88 04 0a } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}