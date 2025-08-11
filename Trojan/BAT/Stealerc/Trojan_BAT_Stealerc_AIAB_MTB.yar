
rule Trojan_BAT_Stealerc_AIAB_MTB{
	meta:
		description = "Trojan:BAT/Stealerc.AIAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 11 1e 19 58 61 11 2e 61 d2 9c 11 2a 13 1e 11 09 17 58 13 09 11 09 11 24 32 a4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}