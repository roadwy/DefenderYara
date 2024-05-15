
rule Trojan_BAT_Zilla_KAQ_MTB{
	meta:
		description = "Trojan:BAT/Zilla.KAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 03 07 6f 90 01 01 00 00 0a 04 58 d1 0d 12 03 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0a 2b 16 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}