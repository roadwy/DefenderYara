
rule TrojanDropper_Win32_Rovnix_B{
	meta:
		description = "TrojanDropper:Win32/Rovnix.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 74 74 72 69 62 20 2d 72 20 2d 73 20 2d 68 25 25 31 } //01 00 
		$a_01_1 = {8b 47 3c 03 c7 0f b7 48 06 0f b7 50 14 6b c9 28 03 c8 8d 74 0a 40 eb 09 66 3d 46 4a 74 0d 83 c6 10 0f b7 06 66 85 c0 75 ef } //00 00 
	condition:
		any of ($a_*)
 
}