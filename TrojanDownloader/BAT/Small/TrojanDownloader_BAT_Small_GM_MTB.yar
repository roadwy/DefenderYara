
rule TrojanDownloader_BAT_Small_GM_MTB{
	meta:
		description = "TrojanDownloader:BAT/Small.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {02 03 6f 1b 00 00 0a 7e 90 01 03 04 03 7e 90 01 03 04 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 d1 90 00 } //1
		$a_02_1 = {02 03 6f 1e 00 00 0a 7e 90 01 03 04 03 7e 90 01 03 04 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 d1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}