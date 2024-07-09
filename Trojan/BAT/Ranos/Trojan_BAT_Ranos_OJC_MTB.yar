
rule Trojan_BAT_Ranos_OJC_MTB{
	meta:
		description = "Trojan:BAT/Ranos.OJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 05 b7 08 11 05 18 6a d8 b7 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 11 05 17 6a d6 13 05 11 05 11 06 31 da } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}