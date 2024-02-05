
rule Trojan_BAT_Zusy_PSWQ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PSWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {19 73 14 00 00 0a 73 15 00 00 0a 13 07 de 19 6f 90 01 01 00 00 0a 72 65 01 00 70 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a dd f6 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}