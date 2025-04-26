
rule Trojan_BAT_Jalapeno_SKKP_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.SKKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 8e 69 20 00 30 00 00 1f 40 28 ?? 00 00 06 0a 02 16 06 02 8e 69 28 ?? 00 00 0a 7e 04 00 00 0a 0b 7e 04 00 00 0a 26 16 73 06 00 00 0a 26 16 73 06 00 00 0a 26 06 0c 7e 04 00 00 0a 16 08 7e 04 00 00 0a 16 7e 04 00 00 0a 28 ?? 00 00 06 0b 07 15 28 ?? 00 00 06 26 2a } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}