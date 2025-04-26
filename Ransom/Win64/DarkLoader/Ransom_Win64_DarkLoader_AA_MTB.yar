
rule Ransom_Win64_DarkLoader_AA_MTB{
	meta:
		description = "Ransom:Win64/DarkLoader.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 63 d0 0f b6 04 0a 41 88 04 ?? 44 88 ?? 0a 41 0f b6 ?? ?? ?? 03 [0-03] 0f b6 c2 0f b6 14 08 32 14 2f 88 17 48 ff c7 48 83 eb 01 90 13 41 ff c1 41 81 e1 ?? ?? ?? ?? 90 13 4d 63 ?? 45 0f b6 ?? ?? 45 03 ?? 41 81 e0 ?? ?? ?? ?? 90 13 49 63 d0 0f b6 04 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}