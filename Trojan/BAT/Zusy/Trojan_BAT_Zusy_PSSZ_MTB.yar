
rule Trojan_BAT_Zusy_PSSZ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PSSZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {7e 26 04 00 04 20 92 c2 66 06 28 90 01 01 06 00 06 28 90 01 01 06 00 06 0a 06 12 01 12 02 28 90 01 01 04 00 06 2c 12 7e f2 07 00 04 07 08 28 90 01 01 07 00 06 26 dd a7 01 00 00 de 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}