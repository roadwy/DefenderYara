
rule TrojanDownloader_O97M_Ursnif_BG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.BG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {23 49 66 20 56 42 41 37 20 54 68 65 6e } //01 00  #If VBA7 Then
		$a_01_1 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 53 75 62 20 53 6c 65 65 70 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 28 42 79 56 61 6c 20 4d 69 6c 6c 69 73 65 63 6f 6e 64 73 20 41 73 20 4c 6f 6e 67 50 74 72 29 } //01 00  Public Declare PtrSafe Sub Sleep Lib "kernel32" (ByVal Milliseconds As LongPtr)
		$a_03_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 90 02 10 2e 69 6e 66 22 2c 20 90 02 10 2e 76 61 6c 75 65 90 00 } //01 00 
		$a_03_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 90 02 10 2e 73 63 74 22 2c 20 90 02 10 2e 76 61 6c 75 65 90 00 } //01 00 
		$a_03_4 = {3d 20 53 68 65 6c 6c 28 22 63 6d 73 74 70 20 2f 6e 69 20 2f 73 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 90 02 10 2e 69 6e 66 22 29 90 00 } //01 00 
		$a_01_5 = {53 6c 65 65 70 20 33 30 30 30 } //00 00  Sleep 3000
	condition:
		any of ($a_*)
 
}