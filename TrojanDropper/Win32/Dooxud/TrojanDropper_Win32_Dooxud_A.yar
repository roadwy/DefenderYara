
rule TrojanDropper_Win32_Dooxud_A{
	meta:
		description = "TrojanDropper:Win32/Dooxud.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 85 90 01 02 ff ff 8a 10 32 94 8d 90 01 02 ff ff 8b 45 08 03 85 90 01 02 ff ff 88 10 e9 90 01 01 ff ff ff 90 00 } //01 00 
		$a_03_1 = {33 c0 66 8b 02 3d 4d 5a 00 00 74 05 e9 90 01 02 00 00 8b 0d 90 01 03 00 8b 55 0c 03 51 3c 89 15 90 01 03 00 a1 90 01 03 00 81 38 50 45 00 00 74 05 e9 90 01 02 00 00 90 00 } //01 00 
		$a_03_2 = {33 d2 66 8b 11 81 fa 4d 5a 00 00 74 05 e9 90 01 02 00 00 a1 90 01 03 00 8b 4d 0c 03 48 3c 89 0d 90 01 03 00 8b 15 90 01 03 00 81 3a 50 45 00 00 74 05 e9 90 01 02 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}