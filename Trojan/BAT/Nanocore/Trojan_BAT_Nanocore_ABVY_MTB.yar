
rule Trojan_BAT_Nanocore_ABVY_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABVY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0d 09 8e 69 8d 90 01 01 00 00 01 13 04 07 08 08 6f 90 01 01 00 00 0a 13 05 09 73 90 01 01 00 00 0a 13 06 00 11 06 11 05 16 73 90 01 01 00 00 0a 13 07 00 11 07 11 04 16 11 04 8e 69 6f 90 01 01 00 00 0a 26 11 07 6f 90 01 01 00 00 0a 00 11 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}