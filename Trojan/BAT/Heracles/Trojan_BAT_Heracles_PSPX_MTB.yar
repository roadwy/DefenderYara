
rule Trojan_BAT_Heracles_PSPX_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PSPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {a2 09 0a 72 90 01 03 70 28 90 01 03 06 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 72 90 01 03 70 20 90 01 03 00 14 14 06 74 90 01 03 1b 6f 90 01 03 0a 26 de 0e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}