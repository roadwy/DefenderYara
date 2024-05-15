
rule TrojanDownloader_O97M_PikaBot_SS_MTB{
	meta:
		description = "TrojanDownloader:O97M/PikaBot.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 69 6c 65 3a 2f 2f 2f 5c 5c 38 35 2e 31 39 35 2e 31 31 35 2e 32 30 5c 73 68 61 72 65 5c 72 65 70 6f 72 74 73 90 02 02 30 32 2e 31 35 2e 90 02 02 32 30 32 34 90 02 02 31 2e 6a 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}