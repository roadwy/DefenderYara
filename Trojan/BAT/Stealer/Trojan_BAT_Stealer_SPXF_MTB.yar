
rule Trojan_BAT_Stealer_SPXF_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SPXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 00 10 00 00 1f 40 28 90 01 03 06 0d 07 16 08 07 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}