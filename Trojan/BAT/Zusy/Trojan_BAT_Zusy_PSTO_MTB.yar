
rule Trojan_BAT_Zusy_PSTO_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PSTO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0c 00 07 06 28 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 26 72 f6 01 00 70 28 90 01 01 00 00 0a 00 00 de 1b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}