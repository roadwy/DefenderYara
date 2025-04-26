
rule Trojan_BAT_Agenttesla_ARAF_MTB{
	meta:
		description = "Trojan:BAT/Agenttesla.ARAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 00 01 00 00 13 07 11 06 17 58 13 08 11 06 20 00 32 01 00 5d 13 09 11 08 20 00 32 01 00 5d 13 0a 07 11 0a 91 11 07 58 13 0b 07 11 09 91 13 0c 08 11 06 1f 16 5d 91 13 0d 11 0c 11 0d 61 13 0e 07 11 09 11 0e 11 0b 59 11 07 5d d2 9c 11 06 17 58 13 06 11 06 20 00 32 01 00 32 a4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}