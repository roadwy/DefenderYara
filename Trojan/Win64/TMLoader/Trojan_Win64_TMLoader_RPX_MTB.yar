
rule Trojan_Win64_TMLoader_RPX_MTB{
	meta:
		description = "Trojan:Win64/TMLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b 4c 24 38 48 8b 44 24 48 ff d0 48 89 c1 48 33 d2 4d 33 c0 4d 33 c9 c7 44 24 20 00 00 00 00 ff d3 48 89 84 24 a0 00 00 00 48 8b 4c 24 40 48 8b 44 24 48 ff d0 48 8b 8c 24 a0 00 00 00 48 89 c2 4d 33 c0 4d 33 c9 c7 44 24 20 02 00 00 80 48 c7 44 24 28 00 00 00 00 ff d6 49 89 c5 4c 89 e9 48 8b 94 24 a8 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}