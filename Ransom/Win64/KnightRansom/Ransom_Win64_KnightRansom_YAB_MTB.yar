
rule Ransom_Win64_KnightRansom_YAB_MTB{
	meta:
		description = "Ransom:Win64/KnightRansom.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 01 d0 48 89 85 ?? ?? ?? ?? 48 8b 85 ?? ?? ?? ?? 8b 00 33 85 ?? ?? ?? ?? 48 8b 95 ?? ?? ?? ?? 89 02 83 85 } //1
		$a_01_1 = {c5 4e ec c4 4e ec c4 4e 48 89 c8 48 f7 e2 48 89 d0 48 c1 e8 03 48 6b c0 1a 48 29 c1 48 89 c8 0f b6 44 05 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}