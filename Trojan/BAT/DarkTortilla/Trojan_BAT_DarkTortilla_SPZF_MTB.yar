
rule Trojan_BAT_DarkTortilla_SPZF_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.SPZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 00 09 07 6f ?? 00 00 0a 00 09 19 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 13 07 73 8e 00 00 0a 13 04 11 04 11 07 17 73 8f 00 00 0a 13 05 11 05 02 16 02 8e 69 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}