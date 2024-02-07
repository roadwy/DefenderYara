
rule Trojan_BAT_AgentTesla_ENT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ENT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c4 d2 c0 d3 af ad 91 04 22 ee 59 a2 43 00 49 89 d6 ed 2f 45 e1 bf fc f0 c0 33 af af cf a5 95 cf 52 42 43 20 49 49 49 2f 2a 45 21 3f 3c d0 c0 53 } //01 00 
		$a_01_1 = {5e 42 21 ed 45 b8 c0 61 09 47 39 3f 3c d0 c0 d3 e9 16 72 64 ed 33 bc be 4a 20 49 49 55 2f 90 b4 68 02 9e 25 a3 26 a1 ad cf bb a9 cf 10 41 41 93 } //01 00 
		$a_01_2 = {a9 cf 5e 42 43 20 49 49 55 2f 2e 45 21 3f 3c d0 c0 d3 af ad cf bb a9 cf 5e 42 43 20 49 49 55 2f 2e 45 21 3f 3c d0 c0 d3 af ad cf bb a9 cf 5e 42 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ENT_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ENT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 00 76 00 61 00 6b 00 6b 00 77 00 70 00 61 00 } //01 00  Ivakkwpa
		$a_01_1 = {00 43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 00 } //01 00 
		$a_01_2 = {00 54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b 00 } //01 00 
		$a_01_3 = {00 57 65 62 52 65 71 75 65 73 74 00 } //01 00  圀扥敒畱獥t
		$a_01_4 = {00 47 65 74 54 79 70 65 00 } //01 00 
		$a_01_5 = {00 47 65 74 4d 65 74 68 6f 64 00 } //01 00 
		$a_01_6 = {00 54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 00 } //01 00  吀楲汰䑥卅牃灹潴敓癲捩健潲楶敤r
		$a_01_7 = {00 53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d 00 } //00 00  匀浹敭牴捩汁潧楲桴m
	condition:
		any of ($a_*)
 
}