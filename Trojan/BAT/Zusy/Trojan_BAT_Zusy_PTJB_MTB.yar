
rule Trojan_BAT_Zusy_PTJB_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PTJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {73 25 00 00 0a 15 16 28 90 01 01 00 00 0a 0b 02 28 90 01 01 00 00 0a 07 17 9a 6f 27 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}