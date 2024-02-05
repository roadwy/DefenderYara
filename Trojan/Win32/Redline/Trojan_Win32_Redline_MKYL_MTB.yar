
rule Trojan_Win32_Redline_MKYL_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKYL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 c7 05 90 01 08 03 44 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 4c 24 90 01 01 31 4c 24 90 01 01 83 3d 90 01 05 75 90 00 } //01 00 
		$a_03_1 = {c1 e8 05 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 4c 24 90 01 01 33 4c 24 90 01 01 8b 44 24 90 01 01 33 c1 2b f0 ba 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}