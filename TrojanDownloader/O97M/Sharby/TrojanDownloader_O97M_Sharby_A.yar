
rule TrojanDownloader_O97M_Sharby_A{
	meta:
		description = "TrojanDownloader:O97M/Sharby.A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 90 02 06 53 68 65 6c 6c 20 28 22 6d 73 68 74 61 20 68 74 74 70 73 3a 2f 2f 90 02 50 2e 68 74 61 22 29 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}