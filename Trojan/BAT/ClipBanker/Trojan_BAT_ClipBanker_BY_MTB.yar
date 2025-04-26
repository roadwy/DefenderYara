
rule Trojan_BAT_ClipBanker_BY_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 09 06 94 58 08 06 94 58 20 ?? ?? ?? 00 5d 13 05 09 06 94 0b 09 06 09 11 05 94 9e 09 11 05 07 9e 06 17 58 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}