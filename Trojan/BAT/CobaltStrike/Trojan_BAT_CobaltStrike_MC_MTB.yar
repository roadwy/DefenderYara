
rule Trojan_BAT_CobaltStrike_MC_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 06 8e 69 6f 90 01 01 00 00 0a 0b 06 07 9a 28 90 01 01 00 00 0a 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}