
rule Trojan_BAT_Zusy_PSOM_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PSOM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 72 6b 11 00 70 28 90 01 03 0a 0a 06 6f 90 01 03 0a 0b 07 6f 90 01 03 0a 0c 7e 90 01 03 0a 0d 08 73 90 01 03 0a 13 04 00 11 04 6f 90 01 03 0a 0d 00 de 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}