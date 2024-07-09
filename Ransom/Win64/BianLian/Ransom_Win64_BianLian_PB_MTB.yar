
rule Ransom_Win64_BianLian_PB_MTB{
	meta:
		description = "Ransom:Win64/BianLian.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //10 Go build ID:
		$a_03_2 = {48 8b 54 24 ?? 48 8d 4a ?? 48 8b 84 24 [0-04] 48 8b 54 24 ?? 48 39 ca 0f 8e [0-04] 48 89 4c 24 ?? 48 8b b4 24 [0-04] 48 89 f7 48 0f af f1 48 03 35 ?? ?? ?? ?? 48 89 b4 24 [0-04] 48 89 c3 48 8b 84 24 [0-04] 48 89 f9 e8 [0-04] 48 8b b4 24 [0-04] 48 39 f0 75 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_03_2  & 1)*10) >=21
 
}