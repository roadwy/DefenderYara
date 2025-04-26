
rule TrojanDownloader_BAT_Fsysna_SK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Fsysna.SK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 0a 11 05 94 58 11 09 11 05 94 58 20 00 01 00 00 5d 13 06 11 0a 11 05 94 13 08 11 0a 11 05 11 0a 11 06 94 9e 11 0a 11 06 11 08 9e 11 05 17 58 13 05 11 05 20 00 01 00 00 32 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}