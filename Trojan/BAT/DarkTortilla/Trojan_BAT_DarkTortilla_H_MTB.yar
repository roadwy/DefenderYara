
rule Trojan_BAT_DarkTortilla_H_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 06 20 00 e1 f5 05 5a 7e 90 01 01 00 00 04 6f 90 01 01 00 00 06 17 58 20 00 e1 f5 05 5a 6f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}