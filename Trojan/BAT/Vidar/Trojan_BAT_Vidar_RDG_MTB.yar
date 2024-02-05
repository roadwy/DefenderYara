
rule Trojan_BAT_Vidar_RDG_MTB{
	meta:
		description = "Trojan:BAT/Vidar.RDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 04 07 59 06 6f 0d 00 00 0a 58 06 6f 0d 00 00 0a 5d 13 04 08 06 } //00 00 
	condition:
		any of ($a_*)
 
}