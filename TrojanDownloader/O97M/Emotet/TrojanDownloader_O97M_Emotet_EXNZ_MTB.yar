
rule TrojanDownloader_O97M_Emotet_EXNZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.EXNZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 39 31 2e 32 34 30 2e 31 31 38 2e 31 37 32 2f [0-04] 2f [0-04] 2f 73 65 2e 68 74 6d 6c } //1
		$a_03_1 = {6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 39 31 2e 32 34 30 2e 31 31 38 2e 31 37 32 2f [0-04] 2f [0-04] 2f 66 65 2e 68 74 6d 6c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}