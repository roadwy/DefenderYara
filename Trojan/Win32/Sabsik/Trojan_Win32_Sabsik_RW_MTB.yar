
rule Trojan_Win32_Sabsik_RW_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 f1 8b 64 45 2d 01 f2 89 44 24 90 01 01 89 54 24 90 01 01 8b 44 24 90 01 01 35 e4 ae 96 27 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Sabsik_RW_MTB_2{
	meta:
		description = "Trojan:Win32/Sabsik.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 89 88 88 88 f7 e1 8b c6 c1 ea 03 8b ca c1 e1 04 2b ca 2b c1 0f b6 80 90 01 04 30 86 90 01 04 83 c6 02 81 fe 7e 07 00 00 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Sabsik_RW_MTB_3{
	meta:
		description = "Trojan:Win32/Sabsik.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {43 72 79 70 74 44 65 73 74 72 6f 79 4b 65 79 } //1 CryptDestroyKey
		$a_81_1 = {44 64 65 43 6f 6e 6e 65 63 74 } //1 DdeConnect
		$a_81_2 = {6d 70 72 2e 64 6c 6c } //1 mpr.dll
		$a_81_3 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //1 CallNextHookEx
		$a_81_4 = {4b 36 6a 75 70 73 70 32 79 57 71 4e 65 74 73 59 31 6a 42 56 65 41 39 6a 67 67 61 77 63 33 63 70 4d 53 6d 67 31 36 32 } //1 K6jupsp2yWqNetsY1jBVeA9jggawc3cpMSmg162
		$a_81_5 = {74 48 71 47 77 73 4b 65 42 62 4d 45 31 37 49 57 37 65 6d 66 49 62 44 6e 48 68 6c 74 30 55 63 58 43 32 34 } //1 tHqGwsKeBbME17IW7emfIbDnHhlt0UcXC24
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}