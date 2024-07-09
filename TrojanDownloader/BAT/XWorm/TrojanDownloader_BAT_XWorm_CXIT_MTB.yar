
rule TrojanDownloader_BAT_XWorm_CXIT_MTB{
	meta:
		description = "TrojanDownloader:BAT/XWorm.CXIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 72 01 00 00 70 28 0e 00 00 06 13 00 38 0f 00 00 00 02 11 01 28 0d 00 00 06 13 02 38 18 00 00 00 28 03 00 00 0a 11 00 6f ?? ?? ?? ?? 28 05 00 00 0a 13 01 } //1
		$a_03_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 66 00 69 00 6c 00 65 00 73 00 2e 00 63 00 61 00 74 00 62 00 6f 00 78 00 2e 00 6d 00 6f 00 65 00 2f [0-1f] 00 70 00 6e 00 67 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}