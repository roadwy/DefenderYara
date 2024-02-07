
rule TrojanDownloader_O97M_Donoff_ST_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.ST!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 65 74 31 2e 63 6f 6f 6d 6f 6e 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 23 20 68 65 68 65 2e 6d 6d 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 2c 20 68 65 68 65 2e 6d 6d 2e 54 61 67 } //01 00  Sheet1.coomon.ShellExecute# hehe.mm.ControlTipText, hehe.mm.Tag
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //01 00 
		$a_01_2 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 68 65 68 65 22 } //00 00  Attribute VB_Name = "hehe"
	condition:
		any of ($a_*)
 
}