
rule Backdoor_Win32_Leenstic_A{
	meta:
		description = "Backdoor:Win32/Leenstic.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 0a 32 88 90 01 04 8b 55 08 03 55 fc 88 0a eb 90 01 01 8b 45 08 03 45 fc 0f be 08 f7 d1 8b 55 08 03 55 fc 88 0a eb 90 00 } //01 00 
		$a_03_1 = {6a 00 6a 02 8d 55 f8 52 6a 23 ff 55 fc 90 01 29 6a 00 6a 04 8d 55 f0 52 6a 07 8b 45 08 50 ff 55 ec 90 00 } //01 00 
		$a_01_2 = {57 69 72 65 73 68 61 72 6b 00 00 00 74 63 70 76 69 65 77 00 4d 53 41 53 43 75 69 00 6d 73 6d 70 65 6e 67 } //01 00 
		$a_01_3 = {73 61 6e 64 62 6f 78 00 68 6f 6e 65 79 00 00 00 76 6d 77 61 72 65 00 00 63 75 72 72 65 6e 74 75 73 65 72 } //01 00 
		$a_01_4 = {25 73 3d 25 73 26 25 73 3d 25 73 26 25 73 3d 25 69 26 25 73 3d 25 73 26 25 73 3d 25 69 } //00 00  %s=%s&%s=%s&%s=%i&%s=%s&%s=%i
	condition:
		any of ($a_*)
 
}