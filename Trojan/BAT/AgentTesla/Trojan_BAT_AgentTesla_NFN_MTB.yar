
rule Trojan_BAT_AgentTesla_NFN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 09 11 04 28 90 01 01 00 00 06 13 05 08 09 11 04 6f 90 01 01 00 00 0a 13 06 11 06 28 90 01 01 00 00 0a 13 07 07 06 11 07 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 08 11 08 2d c8 90 00 } //01 00 
		$a_01_1 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_2 = {47 65 74 50 69 78 65 6c } //00 00  GetPixel
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NFN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 7d 00 00 0a 13 06 11 06 2c 38 06 1f 21 8c 54 00 00 01 07 1f 0e 8c 54 00 00 01 28 7e 00 00 0a 1f 5e 8c 54 00 00 01 28 7f 00 00 0a 28 7e 00 00 0a 28 77 00 00 0a 28 80 00 00 0a 28 81 00 00 0a 0a 2b 12 06 07 28 77 00 00 0a 28 80 00 00 0a 28 81 00 00 0a 0a 08 11 08 12 02 28 82 00 00 0a 13 07 11 07 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NFN_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 44 00 41 00 75 00 3e 00 4d 00 41 00 34 00 43 00 41 00 77 00 41 00 67 00 4c 00 41 00 45 00 44 } //01 00 
		$a_01_1 = {3d 00 3d 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e 00 3e } //01 00 
		$a_01_2 = {41 00 6c 00 42 00 41 00 49 00 41 00 59 00 47 00 41 00 76 00 42 00 41 00 49 00 41 00 55 00 47 00 41 00 75 00 42 00 77 00 62 00 3e 00 43 00 41 00 30 00 42 00 77 00 63 00 41 00 45 00 47 00 41 00 } //01 00  AlBAIAYGAvBAIAUGAuBwb>CA0BwcAEGA
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_4 = {53 74 72 52 65 76 65 72 73 65 } //00 00  StrReverse
	condition:
		any of ($a_*)
 
}