
rule Trojan_BAT_Zilla_RP_MTB{
	meta:
		description = "Trojan:BAT/Zilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {18 5b 17 da 17 d6 8d ?? 00 00 01 0b 02 6f ?? 00 00 0a 17 da 0d 16 13 04 2b 1c 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}