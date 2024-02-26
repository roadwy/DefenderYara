
rule Trojan_BAT_DanaBot_PTAD_MTB{
	meta:
		description = "Trojan:BAT/DanaBot.PTAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {08 28 54 00 00 0a 74 11 00 00 01 13 05 73 55 00 00 0a 13 06 16 0b 2b 21 11 05 07 16 6f 56 00 00 0a 13 0a } //00 00 
	condition:
		any of ($a_*)
 
}