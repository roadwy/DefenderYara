
rule Ransom_Win64_Akira_CCDR_MTB{
	meta:
		description = "Ransom:Win64/Akira.CCDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c1 6b c8 ?? b8 ?? ?? ?? ?? f7 e9 03 d1 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 83 c1 ?? b8 ?? ?? ?? ?? f7 e9 03 d1 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 42 88 4c 05 c1 49 ff c0 49 83 f8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}