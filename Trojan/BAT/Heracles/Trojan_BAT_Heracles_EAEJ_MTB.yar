
rule Trojan_BAT_Heracles_EAEJ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.EAEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0a 17 0b 2b 08 06 07 58 0a 07 17 58 0b 07 1f 0a 31 f3 06 1f 0a 5b 26 2a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}