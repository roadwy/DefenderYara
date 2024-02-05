
rule Trojan_BAT_Cerbu_ACE_MTB{
	meta:
		description = "Trojan:BAT/Cerbu.ACE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 04 09 06 4a 09 8e 69 5d 91 08 06 4a 91 61 d2 6f 90 01 03 0a 06 1a 58 06 4a 54 06 06 1a 58 4a 17 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}