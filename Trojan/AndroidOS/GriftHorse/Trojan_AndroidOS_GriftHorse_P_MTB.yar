
rule Trojan_AndroidOS_GriftHorse_P_MTB{
	meta:
		description = "Trojan:AndroidOS/GriftHorse.P!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {21 00 12 12 6e 20 90 02 04 21 00 6e 10 90 02 04 01 00 0c 02 13 00 00 04 6e 30 90 02 04 02 00 14 02 90 02 04 7f 6e 20 90 02 04 21 00 71 00 90 02 04 00 00 0c 02 6e 20 90 02 04 12 00 0c 02 6e 10 90 02 04 01 00 0c 00 6e 20 90 02 04 02 00 0c 02 14 00 90 02 04 7f 6e 20 90 02 04 01 00 0c 00 6e 20 90 02 04 02 00 0c 02 1a 00 90 02 04 6e 20 90 02 04 02 00 0c 02 1a 00 90 02 04 6e 20 90 02 04 02 00 0c 02 1a 00 90 02 04 6e 20 90 02 04 02 00 0c 02 6e 20 90 02 04 12 00 6e 10 90 02 04 01 00 90 00 } //01 00 
		$a_00_1 = {67 65 74 43 6f 6e 74 65 6e 74 52 65 73 6f 6c 76 65 72 } //01 00  getContentResolver
		$a_00_2 = {4c 63 6f 6d 2f 67 65 6e 65 72 61 6c 66 6c 6f 77 2f 62 72 69 64 67 65 } //01 00  Lcom/generalflow/bridge
		$a_00_3 = {2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 } //01 00  .cloudfront.net
		$a_00_4 = {57 65 62 43 68 72 6f 6d 65 43 6c 69 65 6e 74 } //00 00  WebChromeClient
	condition:
		any of ($a_*)
 
}