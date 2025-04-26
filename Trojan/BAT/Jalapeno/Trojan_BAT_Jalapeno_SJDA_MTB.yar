
rule Trojan_BAT_Jalapeno_SJDA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.SJDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 2b 28 72 ?? ?? 00 70 2b 24 2b 29 2b 2e 72 ?? ?? 00 70 2b 2a 2b 2f 1a 2c f2 2b 31 2b 32 06 16 06 8e 69 6f ?? 00 00 0a 0c de 47 07 2b d5 28 ?? 00 00 0a 2b d5 6f ?? 00 00 0a 2b d0 07 2b cf 28 ?? 00 00 0a 2b cf 6f ?? 00 00 0a 2b ca 07 2b cc 6f ?? 00 00 0a 2b c7 07 2c 06 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}