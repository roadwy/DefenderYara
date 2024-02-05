
rule TrojanDownloader_Win32_Banload_AGY{
	meta:
		description = "TrojanDownloader:Win32/Banload.AGY,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 75 74 6c 6f 6f 6b 65 78 70 70 } //01 00 
		$a_01_1 = {6e 6b 63 2e 63 6f 6d 2e 76 6e } //01 00 
		$a_01_2 = {69 65 78 70 6c 6f 72 65 33 32 } //01 00 
		$a_01_3 = {6a 61 76 61 66 6c 61 73 68 33 } //01 00 
		$a_01_4 = {6c 75 61 20 6e 6f 76 61 00 00 00 00 ff ff ff ff 3a 00 00 00 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d } //00 00 
	condition:
		any of ($a_*)
 
}