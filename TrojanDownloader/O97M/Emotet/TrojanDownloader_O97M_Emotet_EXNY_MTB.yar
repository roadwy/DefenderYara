
rule TrojanDownloader_O97M_Emotet_EXNY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.EXNY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {3a 2f 2f 39 31 2e 32 5e 34 30 2e 31 31 38 2e 31 5e 36 38 2f [0-06] 2f [0-06] 2f [0-01] 73 [0-01] 65 2e [0-01] 68 [0-01] 74 [0-01] 6d [0-01] 6c } //1
		$a_03_1 = {3a 2f 2f 39 31 2e 32 5e 34 30 2e 31 31 38 2e 31 5e 36 38 2f [0-06] 2f [0-06] 2f [0-01] 66 [0-01] 65 2e [0-01] 68 [0-01] 74 [0-01] 6d [0-01] 6c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}