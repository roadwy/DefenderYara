
rule TrojanDownloader_BAT_Heracles_PAZ_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.PAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 26 0b 72 [0-04] 07 28 ?? ?? ?? 06 25 26 0c 08 02 28 ?? ?? ?? 06 74 ?? ?? ?? ?? 28 ?? ?? ?? 06 0a 2b 00 06 2a } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}