
rule Trojan_BAT_Bladabindi_EABQ_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.EABQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 23 00 00 00 00 00 00 3a 40 07 6f a0 00 00 0a 5a 23 00 00 00 00 00 40 50 40 58 28 a1 00 00 0a 28 a2 00 00 0a 28 a3 00 00 0a 0d 12 03 28 a4 00 00 0a 28 60 00 00 0a 0a 00 08 17 58 0c 08 1b fe 04 13 04 11 04 3a b5 ff ff ff } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}