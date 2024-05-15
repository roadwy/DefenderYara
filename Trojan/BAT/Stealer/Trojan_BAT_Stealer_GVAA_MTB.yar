
rule Trojan_BAT_Stealer_GVAA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.GVAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {20 10 00 00 00 fe 0e 02 00 fe 0c 05 00 fe 0c 04 00 fe 0c 18 00 6f 90 01 01 00 00 0a 7e 90 01 01 00 00 04 29 90 01 01 00 00 11 fe 0c 03 00 fe 0c 18 00 6f 90 01 01 00 00 0a 7e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}