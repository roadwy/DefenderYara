
rule Trojan_BAT_Strab_AMMD_MTB{
	meta:
		description = "Trojan:BAT/Strab.AMMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {05 11 0f 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 11 90 01 01 11 90 01 01 6f 90 01 01 00 00 0a a5 90 01 01 00 00 01 61 d2 81 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}