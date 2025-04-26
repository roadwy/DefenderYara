
rule Ransom_Win64_CatB_AD_MTB{
	meta:
		description = "Ransom:Win64/CatB.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {44 0f b6 09 48 8b d9 44 0f b6 51 ?? 44 0f b6 41 ?? 4b 8d 14 ?? 0f b6 4c 57 ?? 4b 8d 04 ?? 32 0c ?? 4b 8d 04 ?? 41 32 c8 41 32 ca 88 0b } //1
		$a_03_1 = {41 32 d0 41 32 d1 88 53 04 0f b6 54 4f ?? 4b 8d 0c ?? 32 14 ?? 4b 8d 04 ?? 44 0f b6 43 ?? 41 32 d3 41 32 d1 } //1
		$a_03_2 = {44 8b c0 8b c8 41 8b d0 48 c1 e9 ?? 83 e1 ?? 48 c1 e8 ?? 48 c1 e1 ?? 83 e0 ?? 48 03 c8 48 c1 ea ?? 83 e2 ?? 48 c1 e2 ?? 42 0f b6 04 19 } //1
		$a_03_3 = {41 8b c8 48 c1 e9 ?? 83 e1 ?? c1 e0 ?? 48 03 d1 42 0f b6 0c 1a 41 8b d0 c1 e1 ?? 03 c1 48 c1 ea ?? 41 8b c8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}