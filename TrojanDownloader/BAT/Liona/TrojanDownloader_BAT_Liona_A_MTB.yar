
rule TrojanDownloader_BAT_Liona_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/Liona.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 07 91 20 55 03 00 00 59 d2 9c 00 07 17 58 0b 07 7e 90 01 01 00 00 04 8e 69 fe 04 0c 08 2d 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}