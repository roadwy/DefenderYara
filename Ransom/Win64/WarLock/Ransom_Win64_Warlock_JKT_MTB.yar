
rule Ransom_Win64_Warlock_JKT_MTB{
	meta:
		description = "Ransom:Win64/Warlock.JKT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 89 c2 48 d3 ea 41 30 14 04 48 83 c0 ?? 48 83 f8 ?? 75 ?? 41 c6 44 24 ?? ?? e9 } //1
		$a_03_1 = {48 89 c1 49 89 d3 83 e1 ?? 48 c1 e1 ?? 49 d3 eb 44 30 5c 05 ?? 48 83 c0 ?? 48 83 f8 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}