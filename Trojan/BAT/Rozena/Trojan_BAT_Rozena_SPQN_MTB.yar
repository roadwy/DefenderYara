
rule Trojan_BAT_Rozena_SPQN_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SPQN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0a 11 0b 9a 13 0c 00 7e 90 01 03 04 11 09 11 0c 72 90 01 03 70 72 90 01 03 70 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 11 09 17 58 13 09 00 11 0b 17 58 13 0b 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}