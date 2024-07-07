
rule TrojanDownloader_BAT_XWormRAT_E_MTB{
	meta:
		description = "TrojanDownloader:BAT/XWormRAT.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 8e 69 0b 07 18 5b 0c 16 0d } //2
		$a_03_1 = {06 09 91 13 90 01 01 06 09 06 07 09 59 17 59 91 9c 06 07 09 59 17 59 11 90 01 01 9c 09 17 58 90 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}