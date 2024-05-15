
rule Trojan_BAT_Zusy_RDG_MTB{
	meta:
		description = "Trojan:BAT/Zusy.RDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {7e 03 00 00 04 6f 36 00 00 0a 02 0e 04 03 8e 69 6f 37 00 00 0a 0a 06 0b } //00 00 
	condition:
		any of ($a_*)
 
}