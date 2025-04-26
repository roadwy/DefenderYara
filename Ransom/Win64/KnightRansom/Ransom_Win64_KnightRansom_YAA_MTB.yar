
rule Ransom_Win64_KnightRansom_YAA_MTB{
	meta:
		description = "Ransom:Win64/KnightRansom.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 08 48 8d 40 04 48 83 ea 01 75 } //1
		$a_03_1 = {64 00 6f 00 c7 44 24 ?? 69 00 2e 00 c7 44 24 ?? 6f 00 72 00 } //1
		$a_03_2 = {48 63 c8 ff c3 48 b8 c5 4e ec c4 4e ec c4 4e 48 f7 e1 48 c1 ea 03 48 6b c2 1a 48 2b c8 0f be 44 0c ?? 66 41 89 06 4d 8d 76 ?? 3b 9c 24 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}