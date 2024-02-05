
rule Trojan_BAT_CobaltStrike_AST_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.AST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 11 00 00 0a 0c 00 73 12 00 00 0a 0d 00 09 20 00 01 00 00 6f 13 00 00 0a 00 09 20 80 00 00 00 6f 14 00 00 0a 00 04 07 20 e8 03 00 00 73 15 00 00 0a 13 04 09 11 04 09 6f 16 00 00 0a 1e 5b 6f 17 00 00 0a 6f 18 00 00 0a 00 09 11 04 09 6f 19 00 00 0a 1e 5b 6f 17 00 00 0a 6f 1a 00 00 0a 00 09 17 6f 1b 00 00 0a 00 09 18 6f 1c 00 00 0a 00 08 09 } //00 00 
	condition:
		any of ($a_*)
 
}