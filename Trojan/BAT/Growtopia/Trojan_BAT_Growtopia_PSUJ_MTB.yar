
rule Trojan_BAT_Growtopia_PSUJ_MTB{
	meta:
		description = "Trojan:BAT/Growtopia.PSUJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 90 01 01 00 00 0a 26 72 15 00 00 70 73 0f 00 00 0a 0a 06 72 33 00 00 70 6f 90 01 01 00 00 0a 00 06 72 4a 0a 00 70 6f 90 01 01 00 00 0a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}