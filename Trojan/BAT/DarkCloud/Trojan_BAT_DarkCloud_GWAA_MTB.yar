
rule Trojan_BAT_DarkCloud_GWAA_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.GWAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 04 11 03 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 16 11 03 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}