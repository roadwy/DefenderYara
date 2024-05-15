
rule Trojan_BAT_Racoon_BR_MTB{
	meta:
		description = "Trojan:BAT/Racoon.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0b 20 b8 00 00 00 28 17 00 00 0a 0b 02 50 06 8f 17 00 00 01 25 47 07 58 d2 52 1f 30 28 17 00 00 0a } //00 00 
	condition:
		any of ($a_*)
 
}