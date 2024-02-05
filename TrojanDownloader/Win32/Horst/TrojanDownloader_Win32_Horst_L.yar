
rule TrojanDownloader_Win32_Horst_L{
	meta:
		description = "TrojanDownloader:Win32/Horst.L,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 } //01 00 
		$a_01_1 = {53 74 61 72 74 53 65 72 76 69 63 65 43 74 72 6c 44 69 73 70 61 74 63 68 65 72 41 } //01 00 
		$a_00_2 = {53 6c 65 65 70 } //01 00 
		$a_01_3 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 43 74 72 6c 48 61 6e 64 6c 65 72 41 } //01 00 
		$a_01_4 = {57 57 57 57 56 53 57 ff 75 0c ff } //01 00 
		$a_01_5 = {74 32 57 57 56 50 56 53 57 ff 75 0c ff } //0a 00 
		$a_01_6 = {6a 00 ff d6 6a 00 ff d6 6a 00 ff d6 6a 00 ff d6 6a 00 ff d6 6a 00 ff d6 6a 00 ff d6 6a 00 ff d6 } //00 00 
	condition:
		any of ($a_*)
 
}