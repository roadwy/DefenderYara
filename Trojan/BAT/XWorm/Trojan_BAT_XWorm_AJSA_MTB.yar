
rule Trojan_BAT_XWorm_AJSA_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AJSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 21 03 11 05 9a 28 ?? ?? 00 0a 20 a1 01 00 00 da b4 13 06 09 11 06 6f ?? ?? 00 0a 00 11 05 17 d6 13 05 11 05 11 04 31 d9 08 09 6f ?? ?? 00 0a 00 08 6f ?? ?? 00 0a 0a 2b 00 06 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}