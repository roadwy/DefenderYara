
rule Ransom_Win32_Snake_GO_MTB{
	meta:
		description = "Ransom:Win32/Snake.GO!MTB,SIGNATURE_TYPE_PEHSTR,37 00 37 00 08 00 00 "
		
	strings :
		$a_01_0 = {73 79 73 74 65 6d 66 75 6e 63 74 69 6f 6e 30 33 36 } //1 systemfunction036
		$a_01_1 = {63 72 79 70 74 61 63 71 75 69 72 65 63 6f 6e 74 65 78 74 } //1 cryptacquirecontext
		$a_01_2 = {49 6d 70 65 72 73 6f 6e 61 74 65 53 65 6c 66 } //1 ImpersonateSelf
		$a_01_3 = {43 72 79 70 74 47 65 6e 52 61 6e 64 6f 6d } //1 CryptGenRandom
		$a_01_4 = {4e 65 74 55 73 65 72 47 65 74 49 6e 66 6f } //1 NetUserGetInfo
		$a_01_5 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_6 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 53 50 6c 45 53 39 45 31 35 35 71 5f 56 2d 62 33 33 30 46 78 2f } //50 Go build ID: "SPlES9E155q_V-b330Fx/
		$a_01_7 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 58 36 6c 4e 45 70 44 68 63 5f 71 67 51 6c 35 36 78 34 64 75 2f } //50 Go build ID: "X6lNEpDhc_qgQl56x4du/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*50+(#a_01_7  & 1)*50) >=55
 
}