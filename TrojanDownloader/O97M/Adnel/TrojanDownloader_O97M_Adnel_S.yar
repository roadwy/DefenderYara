
rule TrojanDownloader_O97M_Adnel_S{
	meta:
		description = "TrojanDownloader:O97M/Adnel.S,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 0a 00 00 01 00 "
		
	strings :
		$a_02_0 = {4d 69 64 24 28 90 02 1f 2c 20 90 02 1f 29 20 3d 20 43 68 72 24 28 90 02 1f 28 4d 69 64 24 28 90 02 1f 2c 20 90 02 1f 2c 20 31 29 29 20 2d 20 90 02 1f 29 90 00 } //01 00 
		$a_02_1 = {53 65 6c 65 63 74 20 43 61 73 65 20 90 02 1f 28 55 43 61 73 65 24 28 4d 69 64 24 28 90 02 1f 2c 20 90 02 1f 2c 20 31 29 29 29 90 00 } //01 00 
		$a_02_2 = {43 61 73 65 20 90 02 1f 20 2b 20 90 02 1f 20 54 6f 20 90 02 1f 20 2b 20 90 00 } //01 00 
		$a_02_3 = {3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 90 02 1f 2c 20 90 02 1f 28 90 02 1f 29 2c 20 56 62 47 65 74 29 90 00 } //01 00 
		$a_02_4 = {3d 20 34 35 20 2a 20 32 0d 0a 46 6f 72 20 90 02 14 20 3d 20 31 20 54 6f 20 4c 65 6e 28 90 02 14 29 0d 0a 53 65 6c 65 63 74 20 43 61 73 65 90 00 } //01 00 
		$a_02_5 = {22 29 29 20 26 20 90 02 14 20 26 20 90 02 14 28 22 90 00 } //01 00 
		$a_02_6 = {3d 20 31 20 54 6f 20 4c 65 6e 28 90 02 14 29 0d 0a 90 02 14 20 3d 20 4d 69 64 28 90 02 14 2c 20 90 02 14 2c 20 31 29 20 26 20 90 02 14 0d 0a 4e 65 78 74 90 00 } //9c ff 
		$a_00_7 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 55 6e 70 72 6f 74 65 63 74 20 50 61 73 73 77 6f 72 64 3a 3d 64 65 72 } //9c ff  ThisWorkbook.Unprotect Password:=der
		$a_01_8 = {77 77 77 2e 7a 65 2d 6d 61 78 2e 64 65 } //9c ff  www.ze-max.de
		$a_00_9 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 63 6c 73 41 64 64 69 74 69 6f 6e 61 6c 42 69 6c 6c 69 6e 67 73 43 6f 6c 75 6d 6e 73 22 } //00 00  Attribute VB_Name = "clsAdditionalBillingsColumns"
	condition:
		any of ($a_*)
 
}