
rule TrojanDownloader_BAT_SnakeKeyLogger_DWL_MTB{
	meta:
		description = "TrojanDownloader:BAT/SnakeKeyLogger.DWL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {49 6b 78 6e 6f 6a 6f 68 64 2e 65 78 65 } //1 Ikxnojohd.exe
		$a_81_1 = {68 74 74 70 3a 2f 2f 31 39 36 2e 32 35 31 2e 39 32 2e 36 39 } //1 http://196.251.92.69
		$a_81_2 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 } //1 Mozilla/5.0
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}