
rule TrojanDownloader_O97M_PShell_D{
	meta:
		description = "TrojanDownloader:O97M/PShell.D,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {20 3d 20 22 5e } //1  = "^
		$a_00_1 = {22 20 2b 20 22 5e } //1 " + "^
		$a_00_2 = {5e 22 20 2b 20 22 } //1 ^" + "
		$a_00_3 = {52 65 73 75 6d 65 20 } //1 Resume 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}