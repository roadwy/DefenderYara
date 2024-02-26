
rule Trojan_BAT_Zusy_LB_MTB{
	meta:
		description = "Trojan:BAT/Zusy.LB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 00 03 02 7b 90 01 02 00 04 04 02 7b 90 01 02 00 04 8e 69 5d 91 61 d2 0a 2b 00 06 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}