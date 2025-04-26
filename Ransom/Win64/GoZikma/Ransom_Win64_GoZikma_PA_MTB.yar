
rule Ransom_Win64_GoZikma_PA_MTB{
	meta:
		description = "Ransom:Win64/GoZikma.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 } //1 Go build ID: 
		$a_01_1 = {2e 6c 6f 63 6b 65 64 } //1 .locked
		$a_03_2 = {0f b6 8c 04 ?? ?? ?? ?? 0f b6 54 04 ?? 31 d1 88 8c 04 ?? ?? ?? ?? 48 ff c0 48 3d ca 01 00 00 7c } //3
		$a_03_3 = {0f b6 5c 04 ?? 31 da 88 94 04 ?? ?? ?? ?? 40 3d ca 01 00 00 7d } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*3+(#a_03_3  & 1)*3) >=5
 
}