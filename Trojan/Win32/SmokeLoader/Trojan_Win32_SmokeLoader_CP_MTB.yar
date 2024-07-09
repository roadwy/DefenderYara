
rule Trojan_Win32_SmokeLoader_CP_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 24 89 44 24 1c 8b 44 24 20 01 44 24 1c 8b 4c 24 10 d3 ee 8b 4c 24 34 8d 44 24 28 c7 05 [0-04] ee 3d ea f4 89 74 24 28 e8 [0-04] 8b 44 24 1c 31 44 24 14 8b 74 24 28 33 74 24 14 81 3d [0-04] 13 02 00 00 75 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}