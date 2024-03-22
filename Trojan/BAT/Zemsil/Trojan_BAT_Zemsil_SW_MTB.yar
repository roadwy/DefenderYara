
rule Trojan_BAT_Zemsil_SW_MTB{
	meta:
		description = "Trojan:BAT/Zemsil.SW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 1f 16 5d 91 61 13 0b 11 0b 07 06 17 58 11 04 5d 91 59 20 00 01 00 00 58 13 0c 07 11 05 11 0c 20 00 01 00 00 5d d2 9c 11 06 07 11 05 91 6f 69 00 00 0a 06 17 58 0a 06 11 04 11 07 17 58 5a fe 04 13 0d 11 0d 2d 9b } //00 00 
	condition:
		any of ($a_*)
 
}