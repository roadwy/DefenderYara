
rule Trojan_BAT_DarkTortilla_O_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.O!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {02 03 61 0b 07 0a 06 2a } //05 00  ̂ୡਇ⨆
		$a_03_1 = {00 00 01 25 16 16 8c 90 01 01 00 00 01 a2 14 28 90 01 01 00 00 0a 14 14 90 00 } //05 00 
		$a_03_2 = {00 00 01 25 17 16 8d 90 01 01 00 00 01 a2 14 14 14 17 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}