
rule Trojan_Win32_SmokeLoader_XIG_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.XIG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c8 c1 e8 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 01 33 c1 31 44 24 90 01 01 81 3d 90 01 08 89 44 24 90 01 01 c7 05 90 01 08 75 90 00 } //01 00 
		$a_03_1 = {6a 00 ff 15 90 01 04 31 7c 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 ff 4c 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}