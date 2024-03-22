
rule Trojan_BAT_Rozena_SPYU_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SPYU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {06 8e 69 20 90 01 03 00 1f 40 28 90 01 03 06 13 05 11 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}