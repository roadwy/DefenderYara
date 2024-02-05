
rule TrojanClicker_Win32_Yabector_B{
	meta:
		description = "TrojanClicker:Win32/Yabector.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {5c 65 42 61 79 2e 6c 6e 6b 00 68 74 74 70 3a 2f 2f 77 77 77 2e 61 64 6f 6e 2d 64 65 6d 61 6e 64 2e 64 65 2f 72 65 64 2f 90 02 05 2f 3f 61 64 64 73 75 62 69 64 3d 51 90 00 } //01 00 
		$a_03_1 = {5c 65 42 61 79 2e 6c 6e 6b 00 68 74 74 70 3a 2f 2f 77 77 77 2e 61 64 6f 6e 2d 64 65 6d 61 6e 64 2e 64 65 2f 72 65 64 2f 90 02 05 2f 3f 61 64 64 73 75 62 69 64 3d 44 90 00 } //01 00 
		$a_03_2 = {5c 65 42 61 79 2e 6c 6e 6b 00 68 74 74 70 3a 2f 2f 77 77 77 2e 61 64 6f 6e 2d 64 65 6d 61 6e 64 2e 64 65 2f 72 65 64 2f 90 02 05 2f 3f 61 64 64 73 75 62 69 64 3d 53 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}