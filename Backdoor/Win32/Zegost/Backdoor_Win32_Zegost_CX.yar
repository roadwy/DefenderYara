
rule Backdoor_Win32_Zegost_CX{
	meta:
		description = "Backdoor:Win32/Zegost.CX,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 38 8b d1 81 e2 ff ff 00 00 8a 54 54 0c 32 da 41 88 1c 38 40 3b c6 72 de } //2
		$a_03_1 = {8a 1c 01 80 f3 ?? 88 18 40 4a 75 f4 } //2
		$a_01_2 = {0d 0a 3c 48 31 3e 34 30 33 20 46 6f 72 62 69 64 64 65 6e 3c 2f 48 31 3e 00 } //1
		$a_01_3 = {00 5f 6b 61 73 70 65 72 73 6b 79 00 } //1 开慫灳牥歳y
		$a_01_4 = {00 5c 73 79 73 6c 6f 67 2e 64 61 74 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}