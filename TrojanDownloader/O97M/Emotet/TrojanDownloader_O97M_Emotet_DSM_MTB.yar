
rule TrojanDownloader_O97M_Emotet_DSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.DSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 65 74 79 6f 63 6b 71 77 2e 76 62 73 } //1 c:\programdata\etyockqw.vbs
	condition:
		((#a_01_0  & 1)*1) >=1
 
}