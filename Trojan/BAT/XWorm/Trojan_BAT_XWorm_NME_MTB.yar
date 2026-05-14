
rule Trojan_BAT_XWorm_NME_MTB{
	meta:
		description = "Trojan:BAT/XWorm.NME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 00 00 06 0a 28 ?? 00 00 06 0b 28 ?? 00 00 06 0c 28 ?? 00 00 06 0d 06 07 08 09 28 ?? 00 00 0a 13 04 11 04 28 ?? 00 00 0a 28 ?? 00 00 0a 13 05 28 ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 06 11 06 6f ?? 00 00 0a 14 14 6f ?? 00 00 0a 26 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}