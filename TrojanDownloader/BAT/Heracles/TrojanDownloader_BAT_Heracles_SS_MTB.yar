
rule TrojanDownloader_BAT_Heracles_SS_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.SS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 04 18 5b 07 11 04 18 6f 05 00 00 0a 1f 10 28 06 00 00 0a 9c 11 04 18 58 13 04 11 04 08 32 df } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}