
rule Ransom_Win64_Basta_YZ_MTB{
	meta:
		description = "Ransom:Win64/Basta.YZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {4d 8d 40 01 f7 eb c1 fa 02 8b c2 c1 e8 1f 03 d0 8b c3 ff c3 8d 0c d2 03 c9 2b c1 48 63 c8 48 8b 44 90 01 02 42 0f b6 8c 09 90 01 04 43 32 8c 08 90 01 04 41 88 4c 00 ff 3b 9c 24 90 01 04 90 13 b8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}