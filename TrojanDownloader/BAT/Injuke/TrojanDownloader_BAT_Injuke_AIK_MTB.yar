
rule TrojanDownloader_BAT_Injuke_AIK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Injuke.AIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 1f 00 00 70 28 32 00 00 06 19 2d 1c 26 28 26 00 00 0a 06 6f 27 00 00 0a 28 28 00 00 0a 28 30 00 00 06 16 2c 06 26 de 09 0a 2b e2 0b 2b f8 } //01 00 
		$a_01_1 = {0b 2b f8 02 06 91 18 2d 15 26 02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e9 06 07 32 de } //00 00 
	condition:
		any of ($a_*)
 
}