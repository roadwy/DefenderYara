
rule Trojan_Win32_Genome_AA{
	meta:
		description = "Trojan:Win32/Genome.AA,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 6a 35 2e 6e 6e 63 6a 2e 6e 65 74 2f 35 66 35 74 6c 6d 61 64 6d 69 6e 2f 63 6f 35 74 75 35 6d 6e 74 2e 61 73 70 } //01 00 
		$a_00_1 = {5f 64 65 6c 65 74 65 6d 65 2e 62 61 74 } //01 00 
		$a_01_2 = {c4 be c2 ed b8 a8 d6 fa b2 e9 d5 d2 c6 f7 } //01 00 
		$a_01_3 = {d6 c7 d6 c7 d7 a8 b0 e6 d7 a5 b0 fc b9 a4 be df } //01 00 
		$a_00_4 = {d6 c7 d6 c7 d7 a5 b0 fc b9 a4 be df 2e 65 78 65 } //01 00 
		$a_01_5 = {cf c2 d4 d8 d5 df bc e0 ca d3 c6 f7 } //01 00 
		$a_00_6 = {b8 eb d7 d3 b9 a4 d7 f7 ca d2 b2 e9 b6 be b9 a4 be df 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}