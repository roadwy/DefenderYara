
rule TrojanDownloader_O97M_Pocrimee_A{
	meta:
		description = "TrojanDownloader:O97M/Pocrimee.A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {70 6f 77 65 72 73 68 65 6c 6c 90 02 80 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 90 02 80 2c 27 25 54 45 4d 50 25 5c 70 75 74 74 79 72 2e 65 78 65 27 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}