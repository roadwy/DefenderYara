
rule Trojan_BAT_DarkTortilla_P_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {01 25 16 09 a2 25 13 0b 14 14 17 8d 90 01 01 00 00 01 25 16 17 9c 25 13 0c 28 90 01 01 00 00 0a 11 0c 90 01 02 00 00 1b 16 91 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}