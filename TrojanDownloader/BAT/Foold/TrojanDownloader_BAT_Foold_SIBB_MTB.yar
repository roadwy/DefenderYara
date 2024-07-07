
rule TrojanDownloader_BAT_Foold_SIBB_MTB{
	meta:
		description = "TrojanDownloader:BAT/Foold.SIBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {07 0e 04 08 6f 90 01 04 08 28 90 01 04 28 90 01 04 6f 90 01 04 0b 07 0e 04 08 6f 90 01 04 08 28 90 01 04 28 90 01 04 6f 90 01 04 0b 07 0e 04 08 6f 90 01 04 08 28 90 01 04 28 90 01 04 6f 90 01 04 0b 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}