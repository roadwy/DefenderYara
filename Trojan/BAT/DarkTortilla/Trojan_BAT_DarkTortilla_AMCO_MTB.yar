
rule Trojan_BAT_DarkTortilla_AMCO_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AMCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 02 16 02 8e 69 6f ?? 00 00 0a 13 06 ?? 13 ?? 38 90 0a 25 00 11 04 74 ?? 00 00 01 6f ?? 00 00 0a 13 05 11 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}