
rule Trojan_BAT_Zilla_KAT_MTB{
	meta:
		description = "Trojan:BAT/Zilla.KAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {5d 02 08 02 8e b7 5d 91 07 08 07 8e b7 5d 91 61 } //00 00 
	condition:
		any of ($a_*)
 
}