
rule Trojan_Win32_Koobface_gen_Q{
	meta:
		description = "Trojan:Win32/Koobface.gen!Q,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3f 70 6f 73 74 3d 74 72 75 65 26 70 61 74 68 3d 62 6c 6f 67 72 65 67 26 76 3d } //01 00 
		$a_01_1 = {3f 70 6f 73 74 3d 74 72 75 65 26 70 61 74 68 3d 63 61 70 74 63 68 61 26 76 3d } //01 00 
		$a_01_2 = {61 3d 73 61 76 65 26 62 3d 67 6f 6f } //01 00 
		$a_01_3 = {23 57 48 49 54 45 4c 41 42 45 4c 00 } //02 00 
		$a_03_4 = {8a cb 6a 01 f6 d9 1b c9 6a 00 81 e1 6b 01 00 00 6a 03 6a 00 83 c1 50 6a 00 51 52 50 ff 15 90 01 04 8b f0 85 f6 89 74 24 14 0f 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}