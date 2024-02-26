
rule Trojan_BAT_Zusy_PTHW_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PTHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 85 01 00 70 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 6f 30 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}