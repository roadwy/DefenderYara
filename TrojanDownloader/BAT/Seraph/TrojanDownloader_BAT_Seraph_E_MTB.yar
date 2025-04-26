
rule TrojanDownloader_BAT_Seraph_E_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {2b 22 2b 27 72 ?? ?? ?? 70 2b 23 00 16 2d 04 2b 24 2b 25 00 17 25 2c 0b 16 2c 24 26 16 2d e1 2b 00 2b 1f 2a 73 ?? ?? ?? 0a 2b d7 0a 2b d6 28 ?? ?? ?? 0a 2b d6 06 2b d9 6f ?? ?? ?? 0a 2b d4 0b 2b da 07 2b de } //10
		$a_81_1 = {53 70 6f 74 69 66 79 } //1 Spotify
		$a_81_2 = {79 6f 75 20 68 61 76 65 20 73 6d 61 72 74 20 63 61 72 } //1 you have smart car
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}