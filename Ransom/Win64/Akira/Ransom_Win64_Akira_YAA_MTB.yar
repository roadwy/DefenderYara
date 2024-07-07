
rule Ransom_Win64_Akira_YAA_MTB{
	meta:
		description = "Ransom:Win64/Akira.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e9 08 44 6b c1 22 41 f7 e8 41 03 d0 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 44 2b c0 b8 90 01 04 41 83 c0 7f 41 f7 e8 41 03 d0 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 44 2b c0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}