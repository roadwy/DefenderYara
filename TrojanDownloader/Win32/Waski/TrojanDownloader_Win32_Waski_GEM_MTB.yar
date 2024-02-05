
rule TrojanDownloader_Win32_Waski_GEM_MTB{
	meta:
		description = "TrojanDownloader:Win32/Waski.GEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 0c c1 e8 02 2b c1 50 f7 f3 83 c2 02 29 16 33 d2 58 f7 f3 03 14 24 81 c2 22 fa 87 35 31 16 83 c6 04 e2 d9 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00 
		$a_01_2 = {44 6f 20 79 6f 75 20 72 65 61 6c 79 20 77 61 6e 74 20 6d 65 3f } //01 00 
		$a_01_3 = {4d 79 20 6e 61 6d 65 20 69 73 20 48 65 72 6f 20 61 6e 64 20 6d 79 20 64 69 63 6b 20 69 73 20 62 72 69 6c 6c 69 61 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}