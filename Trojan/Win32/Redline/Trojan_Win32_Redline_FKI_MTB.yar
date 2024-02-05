
rule Trojan_Win32_Redline_FKI_MTB{
	meta:
		description = "Trojan:Win32/Redline.FKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {51 6a 00 68 90 01 04 68 90 01 04 68 90 01 04 ff 15 90 01 04 8b 4c 24 10 8b 44 24 14 03 44 24 90 01 01 c7 05 90 01 08 33 c7 33 c1 2b f0 8b ce c1 e1 04 89 44 24 14 89 4c 24 90 00 } //01 00 
		$a_03_1 = {8d 3c 33 c7 05 90 01 08 c7 05 90 01 08 89 54 24 14 8b 44 24 28 01 44 24 14 81 3d 90 01 08 75 90 01 01 8d 44 24 38 50 6a 00 ff 15 90 01 04 8b 4c 24 14 33 cf 31 4c 24 10 8b 44 24 10 29 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}