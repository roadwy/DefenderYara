
rule TrojanDownloader_Win32_Zlob_gen_BT{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!BT,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 64 69 72 00 00 00 00 2e 63 6f 6d 2f 72 00 00 6e 64 00 00 74 65 00 00 65 78 00 00 2e 69 65 00 70 3a 2f 2f 77 77 77 00 68 74 74 00 4d 65 6e 75 } //01 00 
		$a_01_1 = {55 52 4c 00 63 68 54 65 72 6d 73 7d 00 00 00 00 3d 7b 73 65 61 72 00 00 3d 25 64 26 71 00 00 00 } //01 00 
		$a_01_2 = {77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 00 00 00 25 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}