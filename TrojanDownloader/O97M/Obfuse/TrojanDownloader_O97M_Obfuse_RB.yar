
rule TrojanDownloader_O97M_Obfuse_RB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //01 00  Sub AutoOpen()
		$a_01_1 = {53 74 72 52 65 76 65 72 73 65 28 22 3a 74 61 6d 72 6f 66 2f 20 74 65 67 20 73 6f 22 20 26 20 22 20 63 69 6d 77 22 29 } //01 00  StrReverse(":tamrof/ teg so" & " cimw")
		$a_03_2 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 20 2b 20 28 90 02 09 20 2a 20 31 30 30 30 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}