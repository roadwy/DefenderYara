
rule TrojanDownloader_Win32_Banload_AGM{
	meta:
		description = "TrojanDownloader:Win32/Banload.AGM,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {6b 61 74 61 72 61 74 61 73 74 72 69 6b 65 00 } //01 00 
		$a_03_1 = {68 6f 73 74 73 79 73 74 65 6d 2e 65 78 65 90 02 0a 6f 66 66 69 63 65 32 90 00 } //01 00 
		$a_03_2 = {69 6d 67 6c 6f 67 2e 65 78 65 90 02 0a 57 6f 72 64 38 90 00 } //01 00 
		$a_01_3 = {2e 00 4c 00 4e 00 4b 00 00 00 } //03 00 
		$a_03_4 = {7e 29 bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 83 ea 90 01 01 e8 90 01 04 8b 55 f4 8d 45 f8 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}