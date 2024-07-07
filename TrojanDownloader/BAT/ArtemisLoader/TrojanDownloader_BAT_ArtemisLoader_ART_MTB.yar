
rule TrojanDownloader_BAT_ArtemisLoader_ART_MTB{
	meta:
		description = "TrojanDownloader:BAT/ArtemisLoader.ART!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 02 7b 90 01 03 04 07 91 61 d2 6f 90 01 03 0a 07 17 58 90 00 } //2
		$a_01_1 = {64 00 77 00 65 00 62 00 2e 00 6c 00 69 00 6e 00 6b 00 } //1 dweb.link
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}