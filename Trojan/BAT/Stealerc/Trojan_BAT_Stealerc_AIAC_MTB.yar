
rule Trojan_BAT_Stealerc_AIAC_MTB{
	meta:
		description = "Trojan:BAT/Stealerc.AIAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 19 11 1e 58 61 11 2e 61 d2 9c 11 2a 13 1e 17 11 09 58 13 09 11 09 11 24 32 a4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}