
rule Trojan_BAT_Nanocore_ABVM_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 14 17 8d 90 01 01 00 00 01 25 16 07 a2 6f 90 01 01 00 00 0a 73 90 01 01 00 00 0a 0c 75 90 01 01 00 00 1b 0d 16 13 04 38 90 01 01 00 00 00 09 11 04 91 13 05 08 11 05 6f 90 01 01 00 00 0a 11 04 17 58 13 04 11 04 09 8e 69 32 e5 08 28 90 01 01 00 00 2b 6f 90 01 01 00 00 0a 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}