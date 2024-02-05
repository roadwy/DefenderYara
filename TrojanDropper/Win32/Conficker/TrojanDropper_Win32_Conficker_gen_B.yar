
rule TrojanDropper_Win32_Conficker_gen_B{
	meta:
		description = "TrojanDropper:Win32/Conficker.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 81 7d f0 d9 07 72 12 90 01 12 0f 00 c0 90 00 } //01 00 
		$a_01_1 = {88 44 06 02 40 3d 00 01 00 00 7c f4 ff 74 24 10 } //01 00 
		$a_01_2 = {83 fe ff 0f 84 04 01 00 00 8b bd } //01 00 
		$a_01_3 = {45 14 e7 ad a6 9c 68 ec } //00 00 
	condition:
		any of ($a_*)
 
}