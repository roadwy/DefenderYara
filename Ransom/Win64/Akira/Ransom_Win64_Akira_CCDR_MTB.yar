
rule Ransom_Win64_Akira_CCDR_MTB{
	meta:
		description = "Ransom:Win64/Akira.CCDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b c1 6b c8 90 01 01 b8 90 01 04 f7 e9 03 d1 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 83 c1 90 01 01 b8 90 01 04 f7 e9 03 d1 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 42 88 4c 05 c1 49 ff c0 49 83 f8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}