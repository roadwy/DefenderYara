
rule Trojan_BAT_DarkTortilla_N_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 0a 14 14 1c 20 90 01 03 5a 28 90 01 01 00 00 06 18 8d 90 01 01 00 00 01 25 17 28 90 01 01 00 00 2b a2 14 14 14 17 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}