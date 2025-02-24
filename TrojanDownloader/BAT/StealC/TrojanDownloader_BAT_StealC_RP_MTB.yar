
rule TrojanDownloader_BAT_StealC_RP_MTB{
	meta:
		description = "TrojanDownloader:BAT/StealC.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 73 03 00 00 06 0a 06 6f 01 00 00 06 00 06 6f 1c 00 00 0a 26 2a } //1
		$a_03_1 = {7d 03 00 00 04 02 72 ?? ?? 00 70 7d ?? ?? 00 04 02 16 28 ?? ?? 00 0a 7d 05 00 00 04 02 72 ?? ?? 00 70 7d 06 00 00 04 02 28 ?? ?? 00 0a 00 00 02 28 ?? ?? 00 06 00 02 28 ?? ?? 00 06 16 fe 01 0a 06 2c 0b } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}