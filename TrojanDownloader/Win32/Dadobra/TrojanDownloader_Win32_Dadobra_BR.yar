
rule TrojanDownloader_Win32_Dadobra_BR{
	meta:
		description = "TrojanDownloader:Win32/Dadobra.BR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 64 62 74 74 65 2e 63 6f 6d 2f 6e 74 74 65 2f 41 74 75 61 6c 69 7a 61 64 61 2e 65 78 65 90 02 0a 63 6d 64 20 2f 6b 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 41 74 75 61 6c 69 7a 61 64 61 2e 65 78 65 90 00 } //01 00 
		$a_03_1 = {68 74 74 70 3a 2f 2f 73 79 64 6c 2e 67 6f 76 2e 63 6e 2f 64 6c 7a 6a 2f 35 2f 35 33 2f 69 6d 67 2f 68 74 74 73 2e 65 78 65 90 02 0a 63 6d 64 20 2f 6b 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 68 74 74 73 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}