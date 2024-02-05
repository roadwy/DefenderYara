
rule TrojanDownloader_BAT_Heracles_SR_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.SR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f 15 00 00 0a 11 04 17 58 13 04 11 04 07 8e 69 32 df } //00 00 
	condition:
		any of ($a_*)
 
}