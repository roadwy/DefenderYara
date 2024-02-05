
rule Trojan_Win32_SmokeLoader_CJ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {8b 44 24 28 89 44 24 20 8b 44 24 24 01 44 24 20 8b 44 24 28 c1 e8 05 89 44 24 14 8b 4c 24 30 8d 44 24 14 c7 05 90 02 04 ee 3d ea f4 e8 90 02 04 8b 44 24 20 31 44 24 10 8b 4c 24 10 31 4c 24 14 81 3d 90 02 04 13 02 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}