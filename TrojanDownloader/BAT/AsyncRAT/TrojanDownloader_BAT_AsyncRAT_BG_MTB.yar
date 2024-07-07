
rule TrojanDownloader_BAT_AsyncRAT_BG_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 20 00 0c 00 00 28 90 01 01 00 00 0a d0 90 01 01 00 00 1b 28 90 01 01 00 00 0a 73 90 01 01 00 00 0a 06 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 72 48 01 00 70 6f 90 01 01 00 00 0a 72 8a 01 00 70 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 74 90 01 01 00 00 1b 0b 07 72 ae 01 00 70 6f 90 01 01 00 00 0a 26 2a 90 00 } //2
		$a_01_1 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6e 6e 65 63 74 65 64 53 74 61 74 65 } //1 InternetGetConnectedState
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}