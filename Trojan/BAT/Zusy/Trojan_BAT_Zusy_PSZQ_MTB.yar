
rule Trojan_BAT_Zusy_PSZQ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PSZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 2a 00 28 ?? 00 00 06 73 01 00 00 0a 13 07 20 00 00 00 00 7e e7 08 00 04 7b 38 09 00 04 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}