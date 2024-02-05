
rule Trojan_BAT_Spynoon_ASBO_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.ASBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {61 59 13 0e 16 13 0f 2b 16 00 11 0e 11 0e 09 11 0f 91 17 58 5d 58 13 0e 00 11 0f 17 58 13 0f 11 0f 09 8e 69 fe 04 13 12 11 12 2d dd } //02 00 
		$a_01_1 = {59 5f 13 0e 11 10 11 0f 11 0b 11 0f 91 11 0e d2 61 d2 9c 00 11 0f 17 58 13 0f 11 0f 11 0b 8e 69 fe 04 13 12 11 12 3a } //00 00 
	condition:
		any of ($a_*)
 
}