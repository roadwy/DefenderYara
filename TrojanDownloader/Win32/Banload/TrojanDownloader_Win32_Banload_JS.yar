
rule TrojanDownloader_Win32_Banload_JS{
	meta:
		description = "TrojanDownloader:Win32/Banload.JS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 61 4e 6f 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 55 73 65 72 6e 61 6d 65 50 61 73 73 77 6f 72 64 07 49 64 53 6f 63 6b 73 } //01 00 
		$a_00_1 = {6d 6f 7a 69 6c 6c 61 2f 33 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 69 6e 64 79 20 6c 69 62 72 61 72 79 29 } //01 00 
		$a_02_2 = {68 74 74 70 3a 2f 2f 73 69 74 65 68 6f 73 74 74 2e 63 6f 6d 2f 90 02 08 2e 72 61 72 90 00 } //01 00 
		$a_00_3 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 69 6e 69 63 69 61 6c 69 7a 61 74 69 6f 6e 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}