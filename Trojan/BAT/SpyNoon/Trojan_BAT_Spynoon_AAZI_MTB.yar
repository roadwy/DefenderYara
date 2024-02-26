
rule Trojan_BAT_Spynoon_AAZI_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AAZI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {09 11 04 5d 13 0a 11 09 11 04 5d 13 0b 07 11 0b 91 11 08 58 13 0c 07 11 0a 91 13 0d 08 09 1f 16 5d 91 13 0e 11 0d 11 0e 61 13 0f } //02 00 
		$a_01_1 = {07 11 0a 11 10 11 08 5d d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}