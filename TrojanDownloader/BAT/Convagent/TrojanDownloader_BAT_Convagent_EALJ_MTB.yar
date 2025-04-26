
rule TrojanDownloader_BAT_Convagent_EALJ_MTB{
	meta:
		description = "TrojanDownloader:BAT/Convagent.EALJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 08 72 35 00 00 70 07 72 35 00 00 70 28 32 00 00 0a 6f 33 00 00 0a 28 34 00 00 0a 9d 00 08 17 58 0c 08 03 fe 04 0d 09 2d d5 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}