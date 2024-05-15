
rule Trojan_BAT_Cerbu_KAAM_MTB{
	meta:
		description = "Trojan:BAT/Cerbu.KAAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 06 07 02 07 91 17 61 d2 9c 00 07 17 58 0b 07 02 8e 69 } //00 00 
	condition:
		any of ($a_*)
 
}