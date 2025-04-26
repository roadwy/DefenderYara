
rule TrojanDownloader_O97M_EncDoc_SLS_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SLS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 22 74 78 74 2e 43 4e 45 2f 6d 6f 63 2e 73 6e 65 64 72 61 67 61 65 6d 73 6f 63 2e 77 77 77 2f 2f 3a 73 70 74 74 68 22 29 } //1 = StrReverse("txt.CNE/moc.snedragaemsoc.www//:sptth")
	condition:
		((#a_01_0  & 1)*1) >=1
 
}