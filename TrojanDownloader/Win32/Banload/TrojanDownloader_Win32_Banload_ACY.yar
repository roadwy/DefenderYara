
rule TrojanDownloader_Win32_Banload_ACY{
	meta:
		description = "TrojanDownloader:Win32/Banload.ACY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 0e 8b 1f 38 d9 75 90 01 01 4a 74 90 01 01 38 fd 75 90 01 01 4a 74 90 01 01 81 e3 00 00 ff 00 81 e1 00 00 ff 00 39 d9 75 90 00 } //01 00 
		$a_00_1 = {76 75 6c 6c 6d 61 73 74 65 72 30 31 } //01 00 
		$a_00_2 = {4c 64 41 72 71 } //01 00 
		$a_00_3 = {4f 63 6f 72 72 65 75 20 75 6d 20 65 72 72 6f 20 69 6e 65 73 70 65 72 61 64 6f } //00 00 
	condition:
		any of ($a_*)
 
}