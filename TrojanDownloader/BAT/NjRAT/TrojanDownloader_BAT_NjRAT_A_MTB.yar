
rule TrojanDownloader_BAT_NjRAT_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/NjRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 16 6f 90 01 01 00 00 0a 13 05 12 05 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 08 17 d6 0c 08 11 04 31 dc 7e 90 01 01 00 00 04 6f 90 01 01 00 00 0a 28 90 01 01 00 00 06 26 de 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}