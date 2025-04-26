
rule TrojanDownloader_BAT_PureCrypter_E_MTB{
	meta:
		description = "TrojanDownloader:BAT/PureCrypter.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 7e ?? 00 00 04 11 03 91 61 d2 6f 02 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}