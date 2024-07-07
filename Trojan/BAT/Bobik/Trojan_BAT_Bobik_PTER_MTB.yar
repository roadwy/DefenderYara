
rule Trojan_BAT_Bobik_PTER_MTB{
	meta:
		description = "Trojan:BAT/Bobik.PTER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 1e 00 00 0a 28 90 01 01 00 00 0a 6f 19 00 00 0a 0b 12 01 28 90 01 01 00 00 0a 6f 20 00 00 0a 00 00 de 0b 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}