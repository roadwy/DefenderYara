
rule Backdoor_Win32_Ixeshe_B_dha{
	meta:
		description = "Backdoor:Win32/Ixeshe.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 76 20 22 41 64 6f 62 65 20 41 73 73 69 73 74 61 6e 74 22 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 22 25 73 22 20 2f 66 00 5c 73 79 73 74 65 6d 33 32 00 00 00 5c 61 63 72 6f 74 72 79 2e 65 78 65 00 } //01 00 
		$a_01_1 = {3c 66 6f 72 6d 20 69 64 3d 22 67 61 69 61 5f 6c 6f 67 69 6e 66 6f 72 6d 22 } //01 00 
		$a_03_2 = {89 65 d8 68 74 ea 43 00 e8 90 01 04 8d 45 b8 50 8b cf c6 45 fc 09 e8 90 01 04 8b c8 e8 90 01 04 50 8d 4d f0 c6 45 fc 0c e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}