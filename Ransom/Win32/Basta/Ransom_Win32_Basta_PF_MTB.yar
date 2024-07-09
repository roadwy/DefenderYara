
rule Ransom_Win32_Basta_PF_MTB{
	meta:
		description = "Ransom:Win32/Basta.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {56 69 73 69 62 6c 65 45 6e 74 72 79 } //1 VisibleEntry
		$a_03_1 = {01 d0 0f b6 30 8b 4d e4 ba ?? ?? ?? ?? 89 c8 f7 ea c1 fa 03 89 c8 c1 f8 1f 29 c2 89 d0 6b c0 2b 29 c1 89 c8 89 c2 8b 45 e0 01 d0 0f b6 00 31 f0 88 03 83 45 e4 01 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}