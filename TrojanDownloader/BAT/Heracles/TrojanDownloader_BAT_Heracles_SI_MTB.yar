
rule TrojanDownloader_BAT_Heracles_SI_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 b8 02 00 70 11 0a 6f ?? ?? ?? 0a 72 c4 02 00 70 11 05 6f ca 00 00 0a 72 d6 02 00 70 11 06 6f ?? ?? ?? 0a 13 0c 11 0c 72 ea 02 00 70 28 ?? ?? ?? 0a 11 07 6f 19 00 00 0a 28 c9 00 00 0a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}