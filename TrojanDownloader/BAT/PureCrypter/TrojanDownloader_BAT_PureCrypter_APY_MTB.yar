
rule TrojanDownloader_BAT_PureCrypter_APY_MTB{
	meta:
		description = "TrojanDownloader:BAT/PureCrypter.APY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {14 0a 38 2c 00 00 00 00 28 11 00 00 0a 02 72 0d 00 00 70 28 08 00 00 06 6f 12 00 00 0a 28 13 00 00 0a 28 06 00 00 06 0a dd 06 00 00 00 26 dd 00 00 00 00 06 2c d1 } //00 00 
	condition:
		any of ($a_*)
 
}