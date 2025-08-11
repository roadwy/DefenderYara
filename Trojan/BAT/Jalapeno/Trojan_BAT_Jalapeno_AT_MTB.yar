
rule Trojan_BAT_Jalapeno_AT_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 10 00 12 01 02 8e 69 28 10 02 00 0a 7d f8 03 00 04 12 01 02 8e 69 7d f7 03 00 04 02 16 07 7b f8 03 00 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}