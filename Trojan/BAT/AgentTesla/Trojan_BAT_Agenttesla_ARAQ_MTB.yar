
rule Trojan_BAT_Agenttesla_ARAQ_MTB{
	meta:
		description = "Trojan:BAT/Agenttesla.ARAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 08 11 07 5d 13 0b 11 04 11 0b 91 11 05 11 08 1f 16 5d 91 61 13 0c 11 0c 11 04 11 08 17 58 11 07 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 0d 11 04 11 0b 11 0d d2 9c 11 08 17 58 13 08 11 08 11 07 11 06 17 58 5a 32 b5 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}