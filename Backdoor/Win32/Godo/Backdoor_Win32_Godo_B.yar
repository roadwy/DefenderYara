
rule Backdoor_Win32_Godo_B{
	meta:
		description = "Backdoor:Win32/Godo.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 79 6e 63 73 74 61 72 74 2e 68 74 6d 6c 3f 69 64 3d 90 02 0f 26 62 64 76 65 72 73 69 6f 6e 3d 90 02 06 26 67 75 69 64 78 3d 90 00 } //01 00 
		$a_01_1 = {6e 65 74 2e 65 78 65 20 6c 6f 63 61 6c 67 72 6f 75 70 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 00 } //01 00 
		$a_03_2 = {68 ff 00 00 00 56 57 ff 15 90 01 04 85 c0 74 06 39 5c 24 90 01 01 75 0b ff 15 90 01 04 83 f8 6d 74 6e 8b 4c 24 0c 88 1c 31 3b f3 75 12 8b 54 24 1c 56 83 c2 14 33 c0 52 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}