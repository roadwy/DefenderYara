
rule Trojan_BAT_Growtopia_PTBQ_MTB{
	meta:
		description = "Trojan:BAT/Growtopia.PTBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {6f 28 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 00 28 90 01 01 00 00 0a 26 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}