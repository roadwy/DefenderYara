
rule Trojan_BAT_Zilla_AMDA_MTB{
	meta:
		description = "Trojan:BAT/Zilla.AMDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 00 1e 8d ?? 00 00 01 0c 07 28 ?? 00 00 0a 05 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 09 16 08 16 1e 28 ?? 00 00 0a 00 06 08 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 03 16 04 8e 69 6f ?? 00 00 0a 13 04 de 16 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}