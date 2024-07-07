
rule TrojanDownloader_O97M_Dotraj_D{
	meta:
		description = "TrojanDownloader:O97M/Dotraj.D,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 90 02 10 22 2c 20 90 02 05 2c 20 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}