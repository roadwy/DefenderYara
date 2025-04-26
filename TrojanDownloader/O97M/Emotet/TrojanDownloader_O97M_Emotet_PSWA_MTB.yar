
rule TrojanDownloader_O97M_Emotet_PSWA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PSWA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {52 45 54 55 [0-0a] 28 29 [0-0f] 52 4e [0-0a] 65 [0-0a] 22 2c 22 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}