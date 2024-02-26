
rule Trojan_BAT_Mardom_SPD_MTB{
	meta:
		description = "Trojan:BAT/Mardom.SPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0b 73 19 00 00 0a 25 07 6f 90 01 03 0a 25 18 6f 90 01 03 0a 25 18 6f 90 01 03 0a 25 6f 90 01 03 0a 06 16 06 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}