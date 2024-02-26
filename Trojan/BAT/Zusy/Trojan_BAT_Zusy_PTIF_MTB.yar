
rule Trojan_BAT_Zusy_PTIF_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PTIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 28 14 00 00 0a 02 28 15 00 00 0a 6f 16 00 00 0a 0a 2b 00 06 2a } //00 00 
	condition:
		any of ($a_*)
 
}