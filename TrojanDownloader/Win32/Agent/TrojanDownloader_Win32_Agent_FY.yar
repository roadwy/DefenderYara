
rule TrojanDownloader_Win32_Agent_FY{
	meta:
		description = "TrojanDownloader:Win32/Agent.FY,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 63 2e 65 78 65 20 73 74 61 72 74 } //01 00  sc.exe start
		$a_00_1 = {5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 72 65 67 73 76 72 33 32 2e 65 78 65 } //01 00  \WINDOWS\system32\regsvr32.exe
		$a_00_2 = {5c 64 72 69 76 65 72 73 5c } //01 00  \drivers\
		$a_00_3 = {41 4d 44 63 6f 72 65 32 } //0a 00  AMDcore2
		$a_00_4 = {35 38 2e 34 39 2e 35 38 2e 32 30 } //0a 00  58.49.58.20
		$a_00_5 = {89 90 68 d4 00 00 89 90 6c d4 00 00 88 90 20 28 01 00 89 90 38 28 01 00 89 90 3c 28 01 00 89 90 40 28 01 00 89 90 34 28 01 00 89 90 44 28 01 00 c7 80 48 28 01 00 80 00 00 00 89 90 4c 28 01 00 89 90 50 28 01 00 } //0a 00 
		$a_02_6 = {8d 85 fc f7 ff ff 68 90 01 02 40 00 50 e8 90 01 02 00 00 8d 85 fc f7 ff ff 56 50 e8 90 01 02 00 00 8d 85 fc f7 ff ff 68 90 01 02 40 00 50 e8 90 01 02 00 00 8d 85 fc ef ff ff 50 8d 85 fc f7 ff ff 50 e8 90 01 02 00 00 8d 85 fc f7 ff ff 68 90 01 02 40 00 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}