
rule Trojan_BAT_Lazy_PTDO_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PTDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 13 6f a6 00 00 06 13 15 11 13 6f a6 00 00 06 13 16 07 11 15 11 16 6f 40 00 00 0a 11 14 } //00 00 
	condition:
		any of ($a_*)
 
}