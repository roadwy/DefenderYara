
rule Trojan_BAT_SmokeLoader_RDG_MTB{
	meta:
		description = "Trojan:BAT/SmokeLoader.RDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 07 11 07 9a 1f 10 28 90 01 01 00 00 0a b4 6f 90 01 01 00 00 0a 00 11 07 17 d6 13 07 11 07 11 06 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}