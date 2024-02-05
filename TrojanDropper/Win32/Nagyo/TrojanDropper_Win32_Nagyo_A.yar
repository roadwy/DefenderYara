
rule TrojanDropper_Win32_Nagyo_A{
	meta:
		description = "TrojanDropper:Win32/Nagyo.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {32 35 36 64 63 35 65 30 65 2d 37 63 34 36 2d 31 31 64 33 2d 62 35 62 66 2d 30 30 30 30 66 38 36 39 35 36 32 31 } //01 00 
		$a_03_1 = {68 00 04 00 00 81 c9 00 b0 08 00 52 8b 90 01 03 8d 90 01 03 6a 02 50 c1 e1 02 51 52 ff 90 00 } //01 00 
		$a_03_2 = {6a 66 6a 00 ff 15 90 01 02 40 00 8b f0 85 f6 75 07 5f 5e 5b 83 c4 44 c3 56 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}