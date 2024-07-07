
rule Ransom_Win64_Akira_AA_MTB{
	meta:
		description = "Ransom:Win64/Akira.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {42 0f b6 4c 0d 90 01 01 83 e9 90 01 01 44 6b c1 90 01 01 b8 09 04 02 81 41 f7 e8 41 03 d0 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 44 2b c0 41 83 c0 7f b8 09 04 02 81 41 f7 e8 41 03 d0 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 44 2b c0 46 88 44 0d 90 01 01 49 ff c1 49 83 f9 90 01 01 72 90 00 } //2
		$a_01_1 = {2e 61 6b 69 72 61 } //2 .akira
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}