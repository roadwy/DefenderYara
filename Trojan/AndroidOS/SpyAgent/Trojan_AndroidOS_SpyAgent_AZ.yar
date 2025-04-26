
rule Trojan_AndroidOS_SpyAgent_AZ{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.AZ,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 38 6e 6f 74 66 74 79 68 6b 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 24 63 6f 6c 6c 65 63 74 41 6e 64 53 65 6e 64 49 6e 69 74 69 61 6c 44 61 74 61 24 31 } //2 w8notftyhk/MainActivity$collectAndSendInitialData$1
		$a_01_1 = {77 38 6e 6f 74 66 74 79 68 6b 2f 41 70 70 53 65 72 76 69 63 65 } //2 w8notftyhk/AppService
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}