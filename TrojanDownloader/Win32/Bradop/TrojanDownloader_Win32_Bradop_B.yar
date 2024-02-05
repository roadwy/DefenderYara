
rule TrojanDownloader_Win32_Bradop_B{
	meta:
		description = "TrojanDownloader:Win32/Bradop.B,SIGNATURE_TYPE_PEHSTR,15 00 15 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0f b6 eb 80 3c 2f 2b 72 45 0f b6 c3 80 3c 07 7a 77 3c 0f b6 c3 80 7c 07 01 2b 72 32 0f b6 c3 80 7c 07 01 7a } //0a 00 
		$a_01_1 = {c1 e8 06 0a d0 80 e2 3f 0f b6 c2 0f b6 80 } //01 00 
		$a_01_2 = {5c 50 72 6f 6a 65 74 6f 73 5c 6e 65 77 68 6f 70 65 5c } //01 00 
		$a_01_3 = {4e 45 57 48 4f 50 45 00 55 8b ec } //01 00 
		$a_01_4 = {4d 41 49 4e 49 43 4f 4e 00 00 00 00 31 30 39 38 37 37 32 38 38 32 } //00 00 
	condition:
		any of ($a_*)
 
}