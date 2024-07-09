
rule Ransom_Win64_Basta_PH_MTB{
	meta:
		description = "Ransom:Win64/Basta.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 89 c8 89 c8 48 ff c1 4c 3b 44 24 ?? 4c 8b 4c 24 ?? 73 ?? 99 41 f7 fa 48 8d 05 ?? ?? ?? ?? 48 63 d2 8a 04 10 48 8b 54 24 40 42 32 04 02 43 88 04 01 eb } //4
		$a_00_1 = {56 69 73 69 62 6c 65 45 6e 74 72 79 } //1 VisibleEntry
	condition:
		((#a_03_0  & 1)*4+(#a_00_1  & 1)*1) >=5
 
}