
rule Ransom_Win64_Ryuk_PD_MTB{
	meta:
		description = "Ransom:Win64/Ryuk.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {41 8b c9 41 f7 e9 [0-03] 41 ff c1 c1 fa ?? 8b c2 c1 e8 1f 03 d0 69 c2 ?? ?? 00 00 2b c8 48 63 c1 8a 84 30 ?? ?? ?? 00 41 30 02 49 ff c2 41 81 f9 ?? ?? 00 00 7c } //1
		$a_02_1 = {41 f6 c2 01 75 06 41 8a 04 29 eb ?? 41 8b c3 41 8b ca 41 f7 ea [0-03] c1 fa ?? 8b c2 c1 e8 1f 03 d0 6b c2 ?? 2b c8 48 63 c1 8a 84 30 ?? ?? ?? 00 41 30 84 31 ?? ?? ?? 00 41 ff c2 49 ff c1 41 83 fa ?? 7c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}