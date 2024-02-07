
rule TrojanDownloader_BAT_PsDow_D_MTB{
	meta:
		description = "TrojanDownloader:BAT/PsDow.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {61 d1 6f 0c 00 00 0a 26 fe } //01 00 
		$a_01_1 = {54 6f 43 68 61 72 41 72 72 61 79 } //00 00  ToCharArray
	condition:
		any of ($a_*)
 
}