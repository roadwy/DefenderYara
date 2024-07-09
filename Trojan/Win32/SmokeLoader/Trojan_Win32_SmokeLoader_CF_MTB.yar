
rule Trojan_Win32_SmokeLoader_CF_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 28 89 44 24 20 8b 44 24 24 01 44 24 20 8b 44 24 28 c1 e8 05 89 44 24 14 8b 4c 24 34 8d 44 24 14 c7 05 [0-04] ee 3d ea f4 e8 [0-04] 8b 44 24 20 31 44 24 10 8b 44 24 10 31 44 24 14 81 3d [0-04] 13 02 00 00 75 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}