
rule Trojan_BAT_Banbra_AMAF_MTB{
	meta:
		description = "Trojan:BAT/Banbra.AMAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 28 ?? 00 00 0a 26 1f ?? 1f ?? 28 ?? 00 00 06 28 ?? 00 00 06 72 ?? ?? 00 70 28 ?? 00 00 0a 0d 08 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}