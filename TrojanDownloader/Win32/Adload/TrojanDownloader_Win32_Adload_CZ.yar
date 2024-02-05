
rule TrojanDownloader_Win32_Adload_CZ{
	meta:
		description = "TrojanDownloader:Win32/Adload.CZ,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1 } //01 00 
		$a_00_1 = {70 6f 70 73 2e 67 6f 2d 64 69 76 61 2e 63 6f 2e 6b 72 2f 68 61 6e 74 69 61 74 } //01 00 
		$a_00_2 = {70 00 6f 00 70 00 73 00 2e 00 67 00 6f 00 2d 00 64 00 69 00 76 00 61 00 2e 00 63 00 6f 00 2e 00 6b 00 72 00 2f 00 68 00 61 00 6e 00 74 00 69 00 61 00 74 00 } //01 00 
		$a_00_3 = {57 69 6e 20 53 65 61 72 63 68 20 66 6f 72 68 61 6e 74 69 61 74 } //01 00 
		$a_00_4 = {70 00 6f 00 70 00 73 00 2f 00 6c 00 6f 00 67 00 73 00 2e 00 76 00 } //00 00 
	condition:
		any of ($a_*)
 
}