
rule TrojanDownloader_O97M_Emotet_RVI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RVI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 65 67 73 76 72 33 32 2e 65 78 65 [0-5f] 22 37 37 37 37 22 2c 22 [0-0a] 52 45 54 55 52 4e [0-0a] 5c 6e 68 74 68 2e 64 6c 6c [0-0a] 5c 6e 68 74 68 2e 64 6c 6c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}