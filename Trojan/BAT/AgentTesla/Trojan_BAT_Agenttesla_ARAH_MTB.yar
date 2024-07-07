
rule Trojan_BAT_Agenttesla_ARAH_MTB{
	meta:
		description = "Trojan:BAT/Agenttesla.ARAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 00 01 00 00 13 08 11 07 17 58 13 09 11 07 20 00 90 01 00 5d 13 0a 11 09 20 00 90 01 00 5d 13 0b 07 11 0b 91 11 08 58 13 0c 07 11 0a 91 13 0d 08 11 07 1f 16 5d 91 13 0e 11 0d 11 0e 61 13 0f 07 11 0a 11 0f 11 0c 59 11 08 5d d2 9c 11 07 17 58 13 07 11 07 20 00 90 01 00 32 a4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}