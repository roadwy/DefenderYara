
rule Trojan_Win32_Redline_DAY_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 54 24 24 8b c1 c1 e8 05 03 44 24 20 03 cb 33 c2 33 c1 2b f0 8b d6 c1 e2 04 81 3d 90 02 04 8c 07 00 00 89 44 24 14 c7 05 90 02 04 00 00 00 00 89 54 24 0c 75 90 00 } //01 00 
		$a_03_1 = {8b 44 24 14 33 c7 31 44 24 0c 8b 44 24 0c 29 44 24 10 81 3d 90 02 04 93 00 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}