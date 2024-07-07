
rule Trojan_BAT_Rozena_SPQI_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SPQI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 09 11 0a 9a 13 0b 00 7e 90 01 03 04 11 08 11 0b 72 90 01 03 70 72 90 01 03 70 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 11 08 17 58 13 08 00 11 0a 17 58 13 0a 11 0a 11 09 8e 69 32 c3 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}