
rule Trojan_BAT_Lazy_SPDD_MTB{
	meta:
		description = "Trojan:BAT/Lazy.SPDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {16 08 09 28 90 01 03 06 6f 90 01 03 0a 16 31 01 2a 11 04 17 58 13 04 11 04 1b 32 e5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}