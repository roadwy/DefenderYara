
rule Ransom_Win32_Eagle_C_dha{
	meta:
		description = "Ransom:Win32/Eagle.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 71 72 73 74 4f 50 67 68 69 6a 6b 6c 6d 39 36 33 6e 6f 75 77 7a 30 32 31 34 35 38 37 2e 2d 4a 4b 4c 4d 4e 76 51 52 53 78 79 54 55 44 45 46 47 48 49 56 57 58 59 5a 61 62 63 64 65 66 41 42 43 } //1 pqrstOPghijklm963nouwz0214587.-JKLMNvQRSxyTUDEFGHIVWXYZabcdefABC
		$a_01_1 = {c7 44 24 08 0f 00 00 00 b8 01 02 04 08 f7 eb c7 44 24 0c 00 00 00 00 25 11 11 11 11 83 e2 01 89 04 24 89 54 24 04 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}