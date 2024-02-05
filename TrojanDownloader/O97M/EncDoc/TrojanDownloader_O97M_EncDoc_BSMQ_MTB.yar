
rule TrojanDownloader_O97M_EncDoc_BSMQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.BSMQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 35 2e 31 35 35 2e 31 36 35 2e 36 33 2f 74 71 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f 50 72 6f 64 75 63 74 5f 44 65 74 61 69 6c 73 5f 30 31 38 5f 52 46 51 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}