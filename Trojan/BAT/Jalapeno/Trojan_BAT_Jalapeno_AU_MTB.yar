
rule Trojan_BAT_Jalapeno_AU_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 07 1f 0f 62 11 0a 75 cc 00 00 1b 11 0c 25 17 58 13 0c 93 11 05 61 60 13 07 1f 09 13 0e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}