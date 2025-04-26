
rule Ransom_Win64_Cyclops_LKV_MTB{
	meta:
		description = "Ransom:Win64/Cyclops.LKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {42 0f b6 04 12 44 09 c8 44 0f a4 c8 08 42 89 84 01 ?? ?? ?? ?? 49 83 fa 1e 77 } //1
		$a_03_1 = {c1 e5 07 29 dd 40 28 e9 88 4c 04 ?? 48 83 c0 01 48 83 f8 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}