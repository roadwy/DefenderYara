
rule Trojan_BAT_CobaltStrike_PC_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 07 09 94 58 20 00 01 00 00 5d 94 13 04 11 08 08 90 01 01 08 91 11 04 61 d2 9c 00 08 17 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}