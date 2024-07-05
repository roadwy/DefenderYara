
rule Trojan_BAT_CobaltStrike_GD_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 28 00 00 01 0b 16 0c 2b 13 07 08 02 08 91 06 08 06 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e7 } //00 00 
	condition:
		any of ($a_*)
 
}