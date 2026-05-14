
rule Ransom_Win64_Lockbit_YBG_MTB{
	meta:
		description = "Ransom:Win64/Lockbit.YBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 89 c0 4d 69 c0 ?? ?? ?? ?? 89 c1 49 c1 e8 20 44 29 c1 d1 e9 44 01 c1 c1 e9 06 41 89 c8 41 c1 e0 07 41 29 c8 44 29 c0 88 84 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}