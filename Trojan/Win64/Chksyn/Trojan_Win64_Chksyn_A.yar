
rule Trojan_Win64_Chksyn_A{
	meta:
		description = "Trojan:Win64/Chksyn.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 01 48 8d 14 24 41 b9 0d 00 00 00 32 02 48 ff c2 49 83 e9 01 75 f5 88 01 48 ff c1 49 83 e8 01 75 de } //01 00 
		$a_03_1 = {6e 65 74 20 73 74 6f 70 20 57 69 6e 44 65 66 65 6e 64 90 02 08 6e 65 74 20 73 74 6f 70 20 4d 70 73 53 76 63 90 00 } //01 00 
		$a_01_2 = {76 3d 25 64 26 73 3d 25 64 26 68 3d 25 64 26 75 6e 3d 25 73 26 6f 3d 25 64 26 63 3d 25 64 26 69 70 3d 25 73 26 73 79 73 3d 25 73 26 75 69 64 3d 25 64 26 77 3d 25 64 } //00 00  v=%d&s=%d&h=%d&un=%s&o=%d&c=%d&ip=%s&sys=%s&uid=%d&w=%d
	condition:
		any of ($a_*)
 
}