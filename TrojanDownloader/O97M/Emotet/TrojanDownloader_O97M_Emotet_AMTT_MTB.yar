
rule TrojanDownloader_O97M_Emotet_AMTT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AMTT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 65 67 73 76 72 33 32 2e 65 78 65 [0-0a] 53 79 73 57 6f 77 36 34 5c [0-0a] 5c 57 69 6e 64 6f 77 73 5c [0-0a] 2c 30 2c [0-0a] 2c 30 2c 30 29 [0-2f] 22 68 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}