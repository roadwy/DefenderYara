
rule TrojanDownloader_Win32_Kaypop_A{
	meta:
		description = "TrojanDownloader:Win32/Kaypop.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 62 6b 70 6f 70 65 00 } //01 00 
		$a_01_1 = {73 74 65 61 6d 73 65 00 70 70 40 00 } //01 00 
		$a_01_2 = {2f 64 6f 77 6e 6c 6f 61 64 5f 76 69 65 77 2f 00 2f 64 61 74 61 2f 66 69 6c 65 73 2f 00 } //01 00 
		$a_01_3 = {69 4d 41 43 3d 25 73 26 69 50 49 44 3d 25 73 26 6d 6f 64 65 41 63 74 3d 25 73 00 } //01 00 
		$a_01_4 = {2e 25 64 2f 6c 6f 67 2f 00 } //00 00 
	condition:
		any of ($a_*)
 
}