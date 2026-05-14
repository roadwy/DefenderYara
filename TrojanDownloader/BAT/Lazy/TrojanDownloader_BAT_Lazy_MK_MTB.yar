
rule TrojanDownloader_BAT_Lazy_MK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Lazy.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 09 11 04 16 11 05 6f 0a 00 00 0a 00 00 08 11 04 16 11 04 8e 69 6f 0b 00 00 0a 25 13 05 16 fe 02 13 06 11 06 2d d9 09 6f 0c 00 00 0a 13 07 de 16 } //15
		$a_01_1 = {00 08 03 16 03 8e 69 6f 0a 00 00 0a 00 00 de 0b 08 2c 07 08 6f 0d 00 00 0a 00 dc } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}