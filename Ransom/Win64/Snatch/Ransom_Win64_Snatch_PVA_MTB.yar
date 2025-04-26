
rule Ransom_Win64_Snatch_PVA_MTB{
	meta:
		description = "Ransom:Win64/Snatch.PVA!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 43 59 4d 6d 4b 73 4d 79 6d 6e 69 68 76 50 54 6a 66 33 35 6b 2f } //1 Go build ID: "CYMmKsMymnihvPTjf35k/
		$a_01_1 = {43 46 4c 4d 4e 50 53 5a } //1 CFLMNPSZ
		$a_01_2 = {63 72 79 70 74 61 63 71 75 69 72 65 63 6f 6e 74 65 78 74 } //1 cryptacquirecontext
		$a_01_3 = {49 6d 70 65 72 73 6f 6e 61 74 65 53 65 6c 66 } //1 ImpersonateSelf
		$a_01_4 = {43 72 79 70 74 47 65 6e 52 61 6e 64 6f 6d } //1 CryptGenRandom
		$a_01_5 = {4e 65 74 55 73 65 72 47 65 74 49 6e 66 6f } //1 NetUserGetInfo
		$a_01_6 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}