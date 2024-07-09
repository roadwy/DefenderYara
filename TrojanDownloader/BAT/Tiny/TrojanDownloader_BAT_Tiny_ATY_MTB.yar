
rule TrojanDownloader_BAT_Tiny_ATY_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 22 00 06 6f 17 00 00 0a 07 9a 6f 18 00 00 0a 14 14 6f 19 00 00 0a 2c 02 de 0e de 03 26 de 00 07 17 58 0b 07 1f 0a 32 d9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_BAT_Tiny_ATY_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Tiny.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 11 04 6f ?? ?? ?? 0a 8c 01 00 00 01 28 ?? ?? ?? 0a 13 05 11 05 28 ?? ?? ?? 06 39 03 00 00 00 11 05 2a 11 04 17 58 13 04 11 04 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_BAT_Tiny_ATY_MTB_3{
	meta:
		description = "TrojanDownloader:BAT/Tiny.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 3b 00 08 13 04 16 13 05 11 04 12 05 28 ?? ?? ?? 0a 00 08 07 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 de 0d 11 05 2c 08 11 04 28 ?? ?? ?? 0a 00 dc 00 09 18 58 0d 09 07 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d b6 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}