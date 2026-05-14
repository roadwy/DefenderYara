
rule Ransom_Win64_Shirna_YBG_MTB{
	meta:
		description = "Ransom:Win64/Shirna.YBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 20 8b 17 01 ?? c7 44 24 ?? 6a 66 38 ef c7 44 24 ?? 6d b7 53 50 } //1
		$a_03_1 = {32 d8 8b d6 0f b6 c3 69 c8 ?? ?? ?? ?? 8b 45 fc 32 c8 89 4d 0c } //4
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*4) >=5
 
}