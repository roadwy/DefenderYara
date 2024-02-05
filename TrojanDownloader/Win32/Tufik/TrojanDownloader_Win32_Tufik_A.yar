
rule TrojanDownloader_Win32_Tufik_A{
	meta:
		description = "TrojanDownloader:Win32/Tufik.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {46 49 47 52 45 53 00 00 } //01 00 
		$a_00_1 = {64 6f 77 6e 6c 6f 61 64 00 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //01 00 
		$a_01_2 = {4d 59 5f 4d 41 49 4e 5f 4a 4e 4a 45 43 54 } //01 00 
		$a_01_3 = {49 45 48 6c 70 72 4f 62 6a 2e 49 45 48 6c 70 72 4f 62 6a 2e 31 } //00 00 
	condition:
		any of ($a_*)
 
}