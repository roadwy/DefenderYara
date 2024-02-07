
rule TrojanDownloader_O97M_Obfuse_HH{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.HH,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 42 79 4e 61 6d 65 20 43 6c 61 73 73 37 2e 56 61 6c 61 61 72 31 2c 20 22 73 61 76 65 74 22 20 26 20 22 6f 66 69 6c 65 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 90 02 08 2e 65 22 20 26 20 22 22 20 2b 20 22 78 65 22 2c 20 32 90 00 } //01 00 
		$a_01_1 = {45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 20 22 4d 45 53 53 41 47 45 28 46 61 6c 73 65 2c 20 22 22 46 69 78 20 4d 61 72 76 22 22 29 22 } //01 00  ExecuteExcel4Macro "MESSAGE(False, ""Fix Marv"")"
		$a_01_2 = {52 6f 63 6b 79 31 2e 4f 70 65 6e 20 4d 65 2e 4c 61 62 65 6c 33 2e 43 61 70 74 69 6f 6e 2c 20 4d 65 2e 54 31 30 5f 54 65 78 74 2e 54 61 67 2c 20 46 61 6c 73 65 } //00 00  Rocky1.Open Me.Label3.Caption, Me.T10_Text.Tag, False
	condition:
		any of ($a_*)
 
}