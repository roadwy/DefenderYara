
rule Ransom_Win64_Basta_AC_MTB{
	meta:
		description = "Ransom:Win64/Basta.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {4c 8b c3 4c 8d 0d 90 02 06 b8 90 01 04 4d 8d 40 90 01 01 f7 eb 8b cb ff c3 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 48 63 c1 42 0f b6 8c 08 90 01 04 43 32 8c 08 90 01 04 48 8b 44 24 90 01 01 41 88 4c 00 90 01 01 3b 9c 24 90 01 04 72 90 01 01 ff 54 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}