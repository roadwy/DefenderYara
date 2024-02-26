
rule Trojan_BAT_Heracles_GPAA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {01 00 06 04 6f 90 01 03 06 0d 09 61 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}