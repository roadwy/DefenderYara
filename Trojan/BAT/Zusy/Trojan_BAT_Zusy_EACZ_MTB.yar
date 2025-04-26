
rule Trojan_BAT_Zusy_EACZ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.EACZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 6f 2a 00 00 0a 13 07 28 2f 00 00 0a 11 07 16 9a 28 30 00 00 0a 6f 31 00 00 0a 13 08 11 08 72 3f 00 00 70 6f 32 00 00 0a 2c 03 11 08 0c 11 07 17 9a 28 30 00 00 0a 13 09 07 11 08 28 20 00 00 0a 11 09 28 33 00 00 0a de 03 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}