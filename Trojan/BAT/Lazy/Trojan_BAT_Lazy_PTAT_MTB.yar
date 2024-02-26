
rule Trojan_BAT_Lazy_PTAT_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PTAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 11 04 02 11 04 91 06 08 93 28 90 01 01 00 00 0a 61 d2 9c 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}