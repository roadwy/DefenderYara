
rule TrojanDownloader_Win32_Whynxy_A{
	meta:
		description = "TrojanDownloader:Win32/Whynxy.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //01 00 
		$a_00_1 = {73 65 72 76 69 63 65 73 2e 64 6c 6c } //01 00 
		$a_01_2 = {44 6e 6c 64 4d 54 73 65 } //01 00 
		$a_01_3 = {58 68 79 77 57 68 6e } //01 00 
		$a_01_4 = {47 43 72 68 6a 6f } //01 00 
		$a_01_5 = {2d 2d 41 61 42 30 33 78 } //01 00 
		$a_01_6 = {6e 61 6d 65 3d 22 64 61 74 65 69 22 3b } //00 00 
	condition:
		any of ($a_*)
 
}