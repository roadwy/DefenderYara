
rule Ransom_Win64_Basta_PH_MTB{
	meta:
		description = "Ransom:Win64/Basta.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {49 89 c8 89 c8 48 ff c1 4c 3b 44 24 90 01 01 4c 8b 4c 24 90 01 01 73 90 01 01 99 41 f7 fa 48 8d 05 90 01 04 48 63 d2 8a 04 10 48 8b 54 24 40 42 32 04 02 43 88 04 01 eb 90 00 } //01 00 
		$a_00_1 = {56 69 73 69 62 6c 65 45 6e 74 72 79 } //00 00  VisibleEntry
		$a_00_2 = {5d 04 00 00 } //c1 80 
	condition:
		any of ($a_*)
 
}