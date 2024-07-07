
rule Trojan_BAT_Mardom_SM_MTB{
	meta:
		description = "Trojan:BAT/Mardom.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 04 16 13 05 1f 10 8d 1d 01 00 01 13 06 06 1a 5a 8d 93 00 00 01 13 07 38 5b 01 00 00 16 13 09 2b 12 11 06 11 09 07 11 04 11 09 58 95 9e 11 09 17 58 13 09 11 09 1f 10 32 e8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}