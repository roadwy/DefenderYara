
rule TrojanDownloader_BAT_Zusy_CCIG_MTB{
	meta:
		description = "TrojanDownloader:BAT/Zusy.CCIG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 2b 17 02 07 8f ?? 00 00 01 25 49 06 07 06 8e 69 5d 93 61 d1 53 07 17 58 0b 07 02 8e 69 32 e3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}