
rule Trojan_Win32_Chksyn_G{
	meta:
		description = "Trojan:Win32/Chksyn.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 01 33 d2 32 44 15 90 01 01 42 83 fa 0d 72 f6 88 01 41 4e 75 ec 90 00 } //01 00 
		$a_03_1 = {80 bd 8c fd ff ff 55 0f 85 90 01 04 80 bd 8d fd ff ff 3a 90 00 } //01 00 
		$a_03_2 = {6e 65 74 20 73 74 6f 70 20 57 69 6e 44 65 66 65 6e 64 90 02 08 6e 65 74 20 73 74 6f 70 20 4d 70 73 53 76 63 90 00 } //01 00 
		$a_01_3 = {76 3d 25 64 26 73 3d 25 64 26 68 3d 25 64 26 75 6e 3d 25 73 26 6f 3d 25 64 26 63 3d 25 64 26 69 70 3d 25 73 26 73 79 73 3d 25 73 26 75 69 64 3d 25 64 26 77 3d 25 64 } //00 00 
	condition:
		any of ($a_*)
 
}