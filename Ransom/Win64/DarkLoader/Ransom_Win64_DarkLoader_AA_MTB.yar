
rule Ransom_Win64_DarkLoader_AA_MTB{
	meta:
		description = "Ransom:Win64/DarkLoader.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 63 d0 0f b6 04 0a 41 88 04 90 01 01 44 88 90 01 01 0a 41 0f b6 90 01 03 03 90 02 03 0f b6 c2 0f b6 14 08 32 14 2f 88 17 48 ff c7 48 83 eb 01 90 13 41 ff c1 41 81 e1 90 01 04 90 13 4d 63 90 01 01 45 0f b6 90 01 02 45 03 90 01 01 41 81 e0 90 01 04 90 13 49 63 d0 0f b6 04 0a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}