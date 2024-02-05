
rule TrojanDropper_Win32_Cutwail_Z{
	meta:
		description = "TrojanDropper:Win32/Cutwail.Z,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d8 c1 e3 03 81 c3 90 01 04 ff 15 90 01 04 8b e5 ff 15 90 01 04 c1 e0 11 2d 90 01 04 03 c3 90 00 } //01 00 
		$a_03_1 = {03 45 fc 31 03 83 e9 90 02 03 7c 08 03 45 f8 83 c3 04 eb 90 01 01 33 c0 8b 5d 90 00 } //01 00 
		$a_01_2 = {b9 2f 0a ab 3d 81 c1 ae c2 10 6d 8b 45 fc 83 c0 04 39 08 75 f9 50 } //00 00 
	condition:
		any of ($a_*)
 
}