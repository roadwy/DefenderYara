
rule Trojan_BAT_Stealer_LA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.LA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 08 07 08 91 06 08 06 6f 90 01 02 00 0a 5d 6f 90 01 02 00 0a 61 d2 9c 00 08 17 58 0c 08 07 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}