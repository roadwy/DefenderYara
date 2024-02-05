
rule TrojanClicker_Win32_Befeenk_A{
	meta:
		description = "TrojanClicker:Win32/Befeenk.A,SIGNATURE_TYPE_PEHSTR,04 00 03 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {4d 4f 56 49 45 00 00 00 ff ff ff ff 10 00 00 00 77 77 77 2e 62 69 67 2d 70 69 6e 6b 2e 6e 65 74 } //01 00 
		$a_01_1 = {2d 62 6f 78 00 00 00 00 ff ff ff ff 05 00 00 00 56 49 44 45 4f 00 00 00 ff ff ff ff 12 } //01 00 
		$a_01_2 = {0b 00 00 00 72 65 67 20 64 65 6c 65 74 65 20 00 ff ff ff ff 16 00 00 00 20 2f 76 20 49 4d 45 5f } //01 00 
		$a_01_3 = {3f 75 69 64 3d 00 00 00 ff ff ff ff 04 00 00 00 26 78 6e 3d 00 00 00 00 61 67 65 6e 74 } //01 00 
		$a_01_4 = {3f 65 78 65 3d 31 26 75 69 64 3d } //01 00 
		$a_01_5 = {6e 6f 63 6f 6f 6b 69 65 00 00 00 00 ff ff ff ff 05 00 00 00 6e 6f 6b 65 79 } //02 00 
		$a_01_6 = {6d 6f 76 69 65 2d 68 2e 63 6f 6d } //01 00 
		$a_01_7 = {63 68 65 63 6b 5f 70 61 79 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}