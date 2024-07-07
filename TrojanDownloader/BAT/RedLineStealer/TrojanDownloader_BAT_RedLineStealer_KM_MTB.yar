
rule TrojanDownloader_BAT_RedLineStealer_KM_MTB{
	meta:
		description = "TrojanDownloader:BAT/RedLineStealer.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 17 59 91 9c } //2
		$a_01_1 = {59 17 59 11 05 9c } //2
		$a_01_2 = {11 03 17 58 13 03 } //2 ̑堗̓
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}