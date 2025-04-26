
rule Ransom_Win64_Basta_TD_MTB{
	meta:
		description = "Ransom:Win64/Basta.TD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 20 83 c0 0e 89 44 24 20 48 8b 44 24 70 48 8b 40 10 48 89 44 24 30 48 8b 44 24 30 48 63 40 3c 48 8b 4c 24 70 48 03 41 10 48 89 44 24 38 8b 44 24 20 99 2b c2 d1 f8 89 44 24 20 48 8b 44 24 38 8b 40 28 48 8b 4c 24 70 48 03 41 10 48 89 44 24 40 48 8b 44 24 40 48 83 c4 68 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}