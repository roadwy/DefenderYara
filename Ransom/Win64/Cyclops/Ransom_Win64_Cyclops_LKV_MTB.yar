
rule Ransom_Win64_Cyclops_LKV_MTB{
	meta:
		description = "Ransom:Win64/Cyclops.LKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {42 0f b6 04 12 44 09 c8 44 0f a4 c8 08 42 89 84 01 90 01 04 49 83 fa 1e 77 90 00 } //01 00 
		$a_03_1 = {c1 e5 07 29 dd 40 28 e9 88 4c 04 90 01 01 48 83 c0 01 48 83 f8 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}