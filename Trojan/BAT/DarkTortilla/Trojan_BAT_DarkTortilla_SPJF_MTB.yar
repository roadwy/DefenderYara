
rule Trojan_BAT_DarkTortilla_SPJF_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.SPJF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 07 73 ?? 00 00 0a 13 04 11 04 11 07 17 73 ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 00 11 05 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 0c 00 00 de 39 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}