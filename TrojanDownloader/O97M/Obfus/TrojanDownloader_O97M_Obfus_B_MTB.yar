
rule TrojanDownloader_O97M_Obfus_B_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfus.B!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {28 22 77 73 63 72 69 70 74 20 2f 2f 6e 6f 6c 6f 67 6f 20 63 3a 5c 43 6f 6c 6f 72 66 6f 6e 74 73 33 32 5c 76 69 73 69 74 63 61 72 64 2e 76 62 73 20 90 02 40 20 63 3a 5c 43 6f 6c 6f 72 66 6f 6e 74 73 33 32 5c 73 65 63 70 69 31 35 2e 65 78 65 90 00 } //01 00 
		$a_01_1 = {73 74 61 72 74 20 63 3a 5c 43 6f 6c 6f 72 66 6f 6e 74 73 33 32 5c 73 65 63 70 69 31 35 2e 65 78 65 } //01 00  start c:\Colorfonts32\secpi15.exe
		$a_01_2 = {4c 6f 61 64 53 63 72 69 70 74 56 42 53 20 47 65 74 4f 62 6a 65 63 74 28 48 61 73 68 54 61 62 6c 65 28 29 29 2c 20 22 63 3a 5c 43 6f 6c 6f 72 66 6f 6e 74 73 33 32 5c 42 34 44 39 44 30 32 31 31 39 2e 63 6d 64 22 2c 20 30 } //00 00  LoadScriptVBS GetObject(HashTable()), "c:\Colorfonts32\B4D9D02119.cmd", 0
	condition:
		any of ($a_*)
 
}