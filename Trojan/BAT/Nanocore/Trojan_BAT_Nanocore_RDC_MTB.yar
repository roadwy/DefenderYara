
rule Trojan_BAT_Nanocore_RDC_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 08 75 02 00 00 1b 11 09 11 07 11 0a 25 17 58 13 0a 91 08 61 d2 9c 11 14 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}