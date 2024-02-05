
rule Trojan_Win32_SmokeLoader_DJ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 1c 8b 44 24 28 8b d7 d3 ea 8b 4c 24 40 03 c7 89 44 24 24 8d 44 24 2c 89 54 24 2c c7 05 90 02 04 ee 3d ea f4 e8 90 02 04 8b 44 24 24 31 44 24 14 81 3d 90 02 04 e6 09 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}