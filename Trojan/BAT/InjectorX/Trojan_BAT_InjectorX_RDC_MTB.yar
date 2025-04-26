
rule Trojan_BAT_InjectorX_RDC_MTB{
	meta:
		description = "Trojan:BAT/InjectorX.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 03 16 03 8e 69 6f 47 00 00 0a 00 11 05 6f 48 00 00 0a 00 11 04 6f 49 00 00 0a 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}