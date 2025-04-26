
rule Trojan_BAT_SharpBlock_psyA_MTB{
	meta:
		description = "Trojan:BAT/SharpBlock.psyA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {12 0e 7c a3 01 00 04 20 01 01 00 00 7d 9c 01 00 04 11 0f 20 00 00 00 08 60 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}