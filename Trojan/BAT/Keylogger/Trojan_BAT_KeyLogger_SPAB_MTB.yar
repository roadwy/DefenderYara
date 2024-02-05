
rule Trojan_BAT_KeyLogger_SPAB_MTB{
	meta:
		description = "Trojan:BAT/KeyLogger.SPAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_03_0 = {06 07 06 8e 69 5d 06 07 06 8e 69 5d 91 09 07 1f 16 5d 91 61 28 90 01 03 0a 06 07 17 58 06 8e 69 5d 91 28 90 01 03 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 07 15 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}