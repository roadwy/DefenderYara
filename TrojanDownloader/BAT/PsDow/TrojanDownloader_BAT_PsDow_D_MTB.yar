
rule TrojanDownloader_BAT_PsDow_D_MTB{
	meta:
		description = "TrojanDownloader:BAT/PsDow.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 d1 6f 0c 00 00 0a 26 fe } //2
		$a_01_1 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}