
rule Trojan_BAT_Nanocore_AMAF_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.AMAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 19 11 0a 11 29 11 22 61 11 1e 19 58 61 11 2c 61 d2 9c 11 22 13 1e 17 11 0a 58 13 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}