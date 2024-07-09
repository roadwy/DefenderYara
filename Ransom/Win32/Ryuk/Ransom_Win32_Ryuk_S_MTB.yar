
rule Ransom_Win32_Ryuk_S_MTB{
	meta:
		description = "Ransom:Win32/Ryuk.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {55 00 4e 00 49 00 51 00 55 00 45 00 5f 00 49 00 44 00 5f 00 44 00 4f 00 5f 00 4e 00 4f 00 54 00 5f 00 52 00 45 00 4d 00 4f 00 56 00 45 00 } //1 UNIQUE_ID_DO_NOT_REMOVE
		$a_01_1 = {52 00 79 00 75 00 6b 00 52 00 65 00 61 00 64 00 4d 00 65 00 2e 00 74 00 78 00 74 00 } //1 RyukReadMe.txt
		$a_01_2 = {59 6f 75 20 77 69 6c 6c 20 72 65 63 65 69 76 65 20 62 74 63 20 61 64 64 72 65 73 73 20 66 6f 72 20 70 61 79 6d 65 6e 74 20 69 6e 20 74 68 65 20 72 65 70 6c 79 20 6c 65 74 74 65 72 } //1 You will receive btc address for payment in the reply letter
		$a_01_3 = {4e 6f 20 73 79 73 74 65 6d 20 69 73 20 73 61 66 65 } //1 No system is safe
		$a_01_4 = {63 72 79 70 74 65 64 20 74 72 79 20 74 6f 20 63 6c 65 61 6e } //1 crypted try to clean
		$a_03_5 = {b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 d0 8d 04 92 03 c0 2b c8 83 f9 09 7e ?? 83 c1 57 eb ?? 83 c1 30 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=3
 
}