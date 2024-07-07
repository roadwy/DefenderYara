
rule TrojanDownloader_BAT_Ader_ARBC_MTB{
	meta:
		description = "TrojanDownloader:BAT/Ader.ARBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {7e 1b 00 00 04 11 04 7e 1b 00 00 04 11 04 91 20 c8 03 00 00 59 d2 9c 00 11 04 17 58 13 04 11 04 7e 1b 00 00 04 8e 69 fe 04 13 05 11 05 2d d0 } //5
		$a_80_1 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 66 69 6e 74 72 61 6e 2e 73 69 74 65 2f 66 6c 2f 39 36 38 } //https://www.fintran.site/fl/968  5
	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*5) >=10
 
}