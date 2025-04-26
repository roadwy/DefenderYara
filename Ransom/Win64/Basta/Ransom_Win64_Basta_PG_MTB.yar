
rule Ransom_Win64_Basta_PG_MTB{
	meta:
		description = "Ransom:Win64/Basta.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 98 48 01 d0 44 0f b6 08 8b 8d ?? ?? ?? ?? ba 83 be a0 2f 89 c8 f7 ea c1 fa 03 89 c8 c1 f8 1f 29 c2 89 d0 6b c0 2b 29 c1 89 c8 48 63 d0 48 8b 85 f0 02 00 00 48 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 fc 02 00 00 01 } //1
		$a_00_1 = {56 69 73 69 62 6c 65 45 6e 74 72 79 } //1 VisibleEntry
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}