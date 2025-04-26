
rule Ransom_Win32_Royal_PA_MTB{
	meta:
		description = "Ransom:Win32/Royal.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_03_0 = {50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 8d 84 24 [0-04] 66 0f 13 44 24 ?? 50 68 [0-04] 66 0f 13 84 24 [0-04] 66 0f 13 84 24 [0-04] 66 0f 13 84 24 [0-04] 66 0f 13 84 24 [0-04] 0f 29 44 24 ?? ff 15 } //10
		$a_03_1 = {8d 84 24 a0 47 00 00 50 ff 15 [0-04] 83 f8 20 74 ?? 6a 00 ff 15 } //10
		$a_03_2 = {85 c0 0f 85 [0-04] 8b 8f [0-04] b8 ab aa aa 2a 8b b7 [0-04] 2b ce ff 45 ?? 83 45 d0 ?? f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 39 45 ?? 8b 45 ?? 72 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10) >=30
 
}