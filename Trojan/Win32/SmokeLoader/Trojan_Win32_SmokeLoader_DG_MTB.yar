
rule Trojan_Win32_SmokeLoader_DG_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 18 8b 45 c4 03 45 a4 89 45 a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 6a 00 e8 90 01 04 8b 5d a0 2b d8 6a 00 e8 90 01 04 03 d8 8b 45 d8 89 18 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_DG_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 37 89 4c 24 20 8b 4c 24 1c 8b d6 d3 ea 8b 4c 24 38 8d 44 24 14 c7 05 90 02 04 ee 3d ea f4 89 54 24 14 e8 90 02 04 8b 44 24 20 31 44 24 10 81 3d 90 02 04 e6 09 00 00 75 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}