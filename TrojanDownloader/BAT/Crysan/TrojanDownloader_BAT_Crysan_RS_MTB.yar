
rule TrojanDownloader_BAT_Crysan_RS_MTB{
	meta:
		description = "TrojanDownloader:BAT/Crysan.RS!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f 30 00 00 0a 11 04 17 58 13 04 11 04 07 8e 69 32 df } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}