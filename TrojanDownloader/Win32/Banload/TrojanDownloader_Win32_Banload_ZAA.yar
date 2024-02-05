
rule TrojanDownloader_Win32_Banload_ZAA{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZAA,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 03 00 "
		
	strings :
		$a_01_0 = {5c 6d 73 64 61 78 38 36 2e 64 6c 6c } //03 00 
		$a_01_1 = {5c 47 62 50 6c 75 67 69 6e 5c 62 62 2e 67 70 63 } //03 00 
		$a_01_2 = {2f 6d 61 73 74 65 74 72 65 64 2e 63 6f 6d 2e 62 72 2f 6e 65 77 2f 6d 6f 72 65 2e 70 68 70 } //01 00 
		$a_01_3 = {2f 6d 77 6d 77 2e 63 6f 6d 2e 62 72 2f } //01 00 
		$a_01_4 = {31 38 37 2e 34 35 2e 32 31 33 2e 36 31 2f 7e 66 72 6f 73 74 66 61 61 2f } //01 00 
		$a_01_5 = {2f 6a 6f 79 63 69 6c 65 6e 65 2e 63 6f 6d 2f 69 6d 61 67 65 6e 73 2f } //01 00 
		$a_01_6 = {2f 64 6a 77 61 6c 74 61 6e 6c 2e 64 6f 6d 69 6e 69 6f 74 65 6d 70 6f 72 61 72 69 6f 2e 63 6f 6d 2f } //00 00 
	condition:
		any of ($a_*)
 
}