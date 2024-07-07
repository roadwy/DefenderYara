
rule TrojanDownloader_O97M_Donoff_CH{
	meta:
		description = "TrojanDownloader:O97M/Donoff.CH,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {45 47 54 22 29 } //1 EGT")
		$a_00_1 = {63 65 78 45 22 29 } //1 cexE")
		$a_00_2 = {6d 69 74 6e 76 6e 6f 6e 65 72 45 22 29 } //1 mitnvnonerE")
		$a_00_3 = {45 54 50 4d 22 29 } //1 ETPM")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}