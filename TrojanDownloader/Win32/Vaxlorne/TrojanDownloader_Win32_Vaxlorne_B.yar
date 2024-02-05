
rule TrojanDownloader_Win32_Vaxlorne_B{
	meta:
		description = "TrojanDownloader:Win32/Vaxlorne.B,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2e 63 6f 2e 6b 72 2f } //02 00 
		$a_01_1 = {64 65 6c 65 74 65 73 65 6c 66 2e 62 61 74 } //02 00 
		$a_01_2 = {4b 69 6c 6c 50 72 6f 63 65 73 73 42 79 46 69 6c 65 4e 61 6d 65 28 25 73 29 } //02 00 
		$a_01_3 = {2e 43 6c 6f 6e 65 41 6e 64 52 65 67 5f 53 65 6c 66 3b } //02 00 
		$a_01_4 = {62 65 66 6f 72 65 20 22 72 65 67 2e 4f 70 65 6e 4b 65 79 28 } //02 00 
		$a_01_5 = {5f 63 6f 75 6e 74 2e 68 74 6d 6c 3f 69 64 3d } //00 00 
	condition:
		any of ($a_*)
 
}