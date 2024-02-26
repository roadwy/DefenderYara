
rule Trojan_BAT_Lazy_AMBH_MTB{
	meta:
		description = "Trojan:BAT/Lazy.AMBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {91 11 04 58 11 04 5d 59 d2 9c 06 17 58 0a } //00 00 
	condition:
		any of ($a_*)
 
}