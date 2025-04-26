
rule Ransom_Win64_Cyclops_LKW_MTB{
	meta:
		description = "Ransom:Win64/Cyclops.LKW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c0 eb 06 0f b6 eb 89 ea c1 e2 07 29 ea 28 d1 88 4c 04 20 48 83 c0 01 48 83 f8 0e 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}