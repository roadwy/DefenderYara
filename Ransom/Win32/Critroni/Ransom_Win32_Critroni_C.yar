
rule Ransom_Win32_Critroni_C{
	meta:
		description = "Ransom:Win32/Critroni.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {eb 29 8b 55 ?? 89 d0 c1 e0 02 01 d0 d1 e0 89 c2 8b 45 14 8b 08 8b 45 ?? 01 c8 8a 40 04 0f be c0 01 d0 83 e8 30 89 45 ?? ff 45 ?? 8b 45 14 8b 10 8b 45 ?? 01 d0 8a 40 04 84 c0 0f 95 c0 84 c0 75 c1 } //1
		$a_03_1 = {eb 2c 8b 55 f4 8b 45 08 8d 0c 02 8b 55 f4 8b 45 08 01 d0 8a 18 8b 45 f4 99 f7 7d 10 89 d0 89 c2 8b 45 0c 01 d0 8a 00 31 d8 88 01 ff 45 f4 8b 45 f4 3b 45 14 0f 9c c0 84 c0 75 c7 83 c4 [1c-2c] } //1
		$a_03_2 = {0f 95 c0 ff 4d ?? 84 c0 75 ?? [0-40] b0 00 ba ?? 00 00 00 89 df 89 d1 f3 aa c6 85 ?? ?? ff ff ?? c6 85 ?? ?? ff ff ?? c6 85 ?? ?? ff ff ?? c6 85 ?? ?? ff ff } //1
		$a_03_3 = {0c 7d 37 8b 84 24 ?? ?? 00 00 0f be 84 04 ?? ?? 00 00 35 ?? [01-ff] 00 00 88 c1 8b 84 24 ?? ?? 00 00 88 8c 04 ?? ?? 00 00 8b 84 24 ?? ?? 00 00 83 c0 01 89 84 24 ?? ?? 00 00 eb bf 8d 05 ?? ?? ?? 90 04 01 03 6[0 04 01 0] 3 08 2d 1f 0[0] c7 84] 24 ?? ?? 00 00 00 00 00 00 c7 84 24 ?? ?? 00 00 00 00 00 00 83 bc 24 ?? ?? 00 00 ?? 7d 37 } //3
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*3) >=3
 
}