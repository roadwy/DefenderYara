
rule Trojan_BAT_Dcstl_PSRU_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.PSRU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 0a 00 00 06 73 0f 00 00 0a 72 4a 01 00 70 72 07 02 00 70 6f 18 00 00 0a 72 07 02 00 70 28 09 00 00 06 72 3f 02 00 70 28 19 00 00 0a 26 72 87 02 00 70 28 19 00 00 0a 26 72 d5 02 00 70 28 19 00 00 0a 26 16 28 1a 00 00 0a 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}