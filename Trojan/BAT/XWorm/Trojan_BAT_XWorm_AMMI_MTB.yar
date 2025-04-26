
rule Trojan_BAT_XWorm_AMMI_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AMMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 09 08 07 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 14 14 6f ?? 00 00 0a 74 ?? 00 00 01 13 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}