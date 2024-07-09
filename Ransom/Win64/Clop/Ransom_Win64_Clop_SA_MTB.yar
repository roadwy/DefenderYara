
rule Ransom_Win64_Clop_SA_MTB{
	meta:
		description = "Ransom:Win64/Clop.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 24 ff c0 25 ?? ?? ?? ?? 88 04 24 0f b6 04 24 48 8b 4c 24 ?? 0f b6 04 01 0f b6 4c 24 ?? 03 c1 25 ?? ?? ?? ?? 88 44 24 } //1
		$a_03_1 = {41 0f b6 14 10 03 ca 81 e1 ?? ?? ?? ?? 48 63 c9 48 8b 54 24 ?? 0f b6 0c 0a 48 ?? ?? ?? ?? 0f b6 04 02 33 c1 8b 4c 24 ?? 48 ?? ?? ?? ?? 88 04 0a e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}