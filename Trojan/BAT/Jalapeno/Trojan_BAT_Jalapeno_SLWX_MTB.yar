
rule Trojan_BAT_Jalapeno_SLWX_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.SLWX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 85 00 00 70 0a 06 28 18 00 00 0a 25 26 0b 28 4a 00 00 0a 25 26 07 16 07 8e 69 6f 4b 00 00 0a 25 26 0a 28 2e 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}