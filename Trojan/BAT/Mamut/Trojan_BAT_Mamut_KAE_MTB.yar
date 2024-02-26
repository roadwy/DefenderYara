
rule Trojan_BAT_Mamut_KAE_MTB{
	meta:
		description = "Trojan:BAT/Mamut.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 07 07 6f 90 01 01 00 00 0a 17 73 90 01 01 00 00 0a 13 08 11 08 02 16 02 8e 69 6f 90 01 01 00 00 0a 11 08 6f 90 01 01 00 00 0a 11 07 6f 90 01 01 00 00 0a 13 04 de 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}