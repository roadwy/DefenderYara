
rule Trojan_Win64_CobaltStrike_HP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 89 c2 48 c1 e2 90 01 01 48 8d 94 0a 90 01 04 83 e1 90 01 01 49 89 5c d3 90 01 01 ba 90 01 04 48 89 d3 48 d3 e3 89 c1 41 90 01 07 83 e1 90 01 01 48 d3 e2 41 09 93 90 01 04 48 83 c4 90 01 01 5b c3 48 83 ec 90 01 01 48 89 4c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}