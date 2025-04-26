
rule TrojanDownloader_BAT_RedLineStealer_KT_MTB{
	meta:
		description = "TrojanDownloader:BAT/RedLineStealer.KT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 06 8e 69 5d 91 fe ?? ?? 00 fe ?? ?? 00 91 61 d2 6f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}