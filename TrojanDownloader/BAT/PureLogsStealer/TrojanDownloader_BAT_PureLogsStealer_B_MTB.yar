
rule TrojanDownloader_BAT_PureLogsStealer_B_MTB{
	meta:
		description = "TrojanDownloader:BAT/PureLogsStealer.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 16 0c 2b ?? 06 08 06 08 91 07 08 07 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 06 8e 69 } //2
		$a_01_1 = {41 6e 74 69 41 6e 61 6c 79 73 69 73 } //2 AntiAnalysis
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}