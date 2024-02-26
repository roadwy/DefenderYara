
rule Trojan_BAT_Zilla_GPA_MTB{
	meta:
		description = "Trojan:BAT/Zilla.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {59 93 61 11 90 01 01 11 90 01 01 11 90 01 01 58 1f 90 01 01 58 11 90 01 01 5d 93 61 d1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}