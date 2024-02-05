
rule Trojan_BAT_DarkTortilla_B_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {02 03 5d 0c } //02 00 
		$a_01_1 = {04 05 60 04 66 05 66 60 5f 0a } //00 00 
	condition:
		any of ($a_*)
 
}