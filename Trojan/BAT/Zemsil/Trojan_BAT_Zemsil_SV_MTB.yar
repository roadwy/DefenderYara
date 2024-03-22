
rule Trojan_BAT_Zemsil_SV_MTB{
	meta:
		description = "Trojan:BAT/Zemsil.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {08 1f 16 5d 91 61 13 0a 11 0a 07 08 17 58 09 5d 91 59 20 00 01 00 00 58 13 0b 07 11 04 11 0b 20 00 01 00 00 5d d2 9c 11 06 07 11 04 91 6f 4c 00 00 0a 08 17 58 0c } //00 00 
	condition:
		any of ($a_*)
 
}