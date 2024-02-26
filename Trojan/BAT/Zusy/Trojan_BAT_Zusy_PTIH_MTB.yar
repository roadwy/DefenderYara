
rule Trojan_BAT_Zusy_PTIH_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PTIH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {20 66 08 00 00 28 90 01 01 00 00 0a 00 72 01 00 00 70 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 0a 06 0b 2b 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}