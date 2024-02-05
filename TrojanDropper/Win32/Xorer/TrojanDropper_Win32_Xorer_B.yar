
rule TrojanDropper_Win32_Xorer_B{
	meta:
		description = "TrojanDropper:Win32/Xorer.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a c1 2c 61 3c 19 77 90 01 01 80 e9 47 eb 90 01 01 8a c1 2c 30 3c 09 90 00 } //01 00 
		$a_03_1 = {fe c2 0f be fa 81 ff 90 01 02 00 00 75 02 32 d2 30 14 30 40 3b c1 7c e9 90 00 } //01 00 
		$a_01_2 = {75 02 33 c0 30 04 32 42 40 3b d1 7c ef } //00 00 
	condition:
		any of ($a_*)
 
}