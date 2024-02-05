
rule Trojan_BAT_Bladabindi_DD_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {a2 00 06 19 28 2f 00 00 06 a2 00 06 1a 28 30 00 00 06 a2 00 06 1b 28 31 00 00 06 a2 00 06 28 02 00 00 0a 28 03 00 00 0a 6f 04 00 00 0a 6f 05 00 00 0a 14 14 6f 06 00 00 0a 26 00 2a } //01 00 
		$a_01_1 = {a2 00 09 1b 28 31 00 00 06 a2 00 09 28 01 00 00 0a 0a 06 28 02 00 00 0a 0b 28 03 00 00 0a 07 6f 04 00 00 0a 6f 05 00 00 0a 14 14 6f 06 00 00 0a 28 07 00 00 0a 0c 00 2a } //00 00 
	condition:
		any of ($a_*)
 
}