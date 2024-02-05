
rule TrojanDropper_Win32_Conficker_gen_A{
	meta:
		description = "TrojanDropper:Win32/Conficker.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 1a 99 59 f7 f9 80 c2 61 88 14 1e 46 3b f7 7c e9 c6 04 3b 00 } //01 00 
		$a_01_1 = {66 81 7d f0 d9 07 } //01 00 
		$a_03_2 = {75 15 6a 04 50 8d 85 90 01 02 ff ff 50 ff d3 eb 07 90 00 } //01 00 
		$a_03_3 = {50 ff d7 6a 35 8d 85 90 09 18 00 35 90 01 04 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}