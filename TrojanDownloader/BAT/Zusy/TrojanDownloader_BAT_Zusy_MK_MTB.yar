
rule TrojanDownloader_BAT_Zusy_MK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Zusy.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 17 00 00 0a 72 ?? 00 00 70 28 18 00 00 0a 06 28 19 00 00 0a 00 28 17 00 00 0a 72 ?? 00 00 70 28 18 00 00 0a 28 1a 00 00 0a 26 28 1b 00 00 0a 00 2a } //35
	condition:
		((#a_03_0  & 1)*35) >=35
 
}