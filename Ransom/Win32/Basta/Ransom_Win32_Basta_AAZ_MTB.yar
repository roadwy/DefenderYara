
rule Ransom_Win32_Basta_AAZ_MTB{
	meta:
		description = "Ransom:Win32/Basta.AAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 c9 0f af c8 8b 44 24 24 66 2b 0c f8 66 01 0c 7a a1 ?? ?? ?? ?? 8a 44 43 1a 0a 44 24 14 30 04 2f a1 ?? ?? ?? ?? 0f b7 4c 42 2e 8d 34 42 b8 3f 15 00 00 2b 05 ?? ?? ?? ?? 2b 05 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}