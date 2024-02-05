
rule Trojan_BAT_Rozena_PSTC_MTB{
	meta:
		description = "Trojan:BAT/Rozena.PSTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {35 00 00 0a 6f 90 01 01 00 00 0a d0 04 00 00 02 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 74 04 00 00 02 13 04 2b 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}