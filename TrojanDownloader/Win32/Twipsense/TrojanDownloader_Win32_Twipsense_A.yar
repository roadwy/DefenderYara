
rule TrojanDownloader_Win32_Twipsense_A{
	meta:
		description = "TrojanDownloader:Win32/Twipsense.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 64 65 76 65 6c 6f 70 65 6d 65 6e 74 5c 70 72 6f 6a 65 63 74 73 5c 66 6c 6f 6f 64 5f 6c 6f 61 64 5c 52 65 6c 65 61 73 65 5c 66 6c 6f 6f 64 5f 6c 6f 61 64 2e 70 64 62 } //02 00 
		$a_01_1 = {32 69 70 2e 72 75 } //02 00 
		$a_01_2 = {2f 6c 69 63 65 6e 73 65 5f 6d 6f 6e 69 74 6f 72 2f 31 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}