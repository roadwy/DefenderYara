
rule Ransom_Win64_Donut_HUT_MTB{
	meta:
		description = "Ransom:Win64/Donut.HUT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 c9 45 29 c9 89 c8 31 d2 66 41 f7 f6 49 81 f9 4b 02 00 00 74 1a 6b c0 33 44 89 c2 28 c2 42 30 94 0c ?? ?? ?? ?? 49 ff c1 41 fe c0 ff c1 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}