
rule Ransom_Win32_Play_PAA_MTB{
	meta:
		description = "Ransom:Win32/Play.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 44 24 08 8b 4c 24 90 01 01 0b c8 8b 4c 24 90 01 01 75 90 01 01 8b 44 24 04 f7 e1 90 00 } //01 00 
		$a_03_1 = {f7 e1 8b d8 8b 44 24 90 01 01 f7 64 24 90 01 01 03 d8 8b 44 24 90 01 01 f7 e1 03 d3 5b 90 00 } //01 00 
		$a_03_2 = {53 f7 e1 8b d8 8b 44 24 90 01 01 f7 64 24 90 01 01 03 d8 8b 44 24 90 01 01 f7 e1 03 d3 5b 90 00 } //01 00 
		$a_03_3 = {55 8b ec 81 ec 90 01 04 a1 90 01 04 33 c5 89 45 90 01 01 53 56 57 83 ec 08 b0 40 b3 73 3a c3 75 90 01 01 81 c4 90 01 04 83 c4 08 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}