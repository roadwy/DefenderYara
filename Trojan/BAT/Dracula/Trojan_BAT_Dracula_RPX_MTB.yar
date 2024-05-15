
rule Trojan_BAT_Dracula_RPX_MTB{
	meta:
		description = "Trojan:BAT/Dracula.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {a2 25 20 01 00 00 00 20 6f 00 00 00 28 0a 00 00 0a a2 25 20 02 00 00 00 20 61 00 00 00 28 0a 00 00 0a a2 25 20 03 00 00 00 20 64 00 00 00 28 0a 00 00 0a a2 25 20 04 00 00 00 20 65 00 00 00 28 0a 00 00 0a a2 25 20 05 00 00 00 20 72 00 00 00 28 0a 00 00 0a a2 25 20 06 00 00 00 20 20 00 00 00 28 0a 00 00 0a a2 25 20 } //00 00 
	condition:
		any of ($a_*)
 
}