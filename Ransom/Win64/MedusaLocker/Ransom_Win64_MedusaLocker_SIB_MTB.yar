
rule Ransom_Win64_MedusaLocker_SIB_MTB{
	meta:
		description = "Ransom:Win64/MedusaLocker.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1b 00 05 00 00 "
		
	strings :
		$a_02_0 = {31 00 4a 00 [0-0a] 2e 00 65 00 78 00 65 } //2
		$a_80_1 = {2e 62 6f 6f 74 } //.boot  1
		$a_80_2 = {2e 74 68 65 6d 69 64 61 } //.themida  5
		$a_02_3 = {48 01 d8 83 38 00 74 ?? 58 eb ?? 58 b9 ?? ?? ?? ?? 83 e9 ?? 48 01 c1 53 6a ?? 53 6a ?? 51 ff d0 5b b8 ?? ?? ?? ?? 48 01 d8 5d 5f 5e 5a 59 5b ff e0 } //10
		$a_02_4 = {8a 06 48 ff c6 88 07 48 ff c7 bb [0-04] 00 d2 75 ?? 8a 16 48 ff c6 10 d2 73 ?? 00 d2 75 ?? 8a 16 48 ff c6 10 d2 73 ?? 31 c0 00 d2 75 ?? 8a 16 48 ff c6 10 d2 0f 83 ?? ?? ?? ?? 00 d2 75 ?? 8a 16 48 ff c6 10 d2 11 c0 00 d2 75 ?? 8a 16 48 ff c6 10 d2 11 c0 00 d2 75 ?? 8a 16 48 ff c6 10 d2 11 c0 00 d2 75 ?? 8a 16 48 ff c6 10 d2 11 c0 74 ?? 57 89 c0 48 29 c7 8a 07 5f 88 07 48 ff c7 bb ?? ?? ?? ?? eb } //10
	condition:
		((#a_02_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*5+(#a_02_3  & 1)*10+(#a_02_4  & 1)*10) >=27
 
}