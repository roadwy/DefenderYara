
rule Trojan_BAT_Zilla_KAL_MTB{
	meta:
		description = "Trojan:BAT/Zilla.KAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {1d 58 61 d2 13 20 11 23 16 91 11 23 18 91 1e 62 60 11 20 19 62 58 13 1d 16 13 18 16 13 0b } //00 00 
	condition:
		any of ($a_*)
 
}