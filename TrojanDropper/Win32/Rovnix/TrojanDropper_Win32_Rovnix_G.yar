
rule TrojanDropper_Win32_Rovnix_G{
	meta:
		description = "TrojanDropper:Win32/Rovnix.G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {3c 00 77 d0 83 7d 14 00 75 06 81 f3 90 01 04 89 5d fc 61 90 00 } //01 00 
		$a_01_1 = {8b 45 9c 83 c0 08 89 45 98 ff 75 80 ff 75 84 ff 75 88 ff 75 8c ff 35 e8 c0 42 00 ff 35 e4 c0 42 00 ff 75 98 ff 55 98 } //00 00 
	condition:
		any of ($a_*)
 
}