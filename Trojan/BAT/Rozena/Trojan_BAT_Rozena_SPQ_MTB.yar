
rule Trojan_BAT_Rozena_SPQ_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 17 58 13 06 18 13 08 2b 0d 11 06 11 08 5d 2c 0c 11 08 17 58 13 08 11 08 11 06 31 ed 11 08 11 06 33 06 11 07 17 58 13 07 11 07 11 05 32 d0 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}