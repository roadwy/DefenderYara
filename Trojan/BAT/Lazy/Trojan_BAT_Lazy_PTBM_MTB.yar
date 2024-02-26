
rule Trojan_BAT_Lazy_PTBM_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PTBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 02 11 00 70 28 90 01 01 00 00 0a 0b 06 28 90 01 01 00 00 0a 07 6f 24 00 00 0a 6f 25 00 00 0a 26 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}