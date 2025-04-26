
rule Trojan_Win32_Babar_NK_MTB{
	meta:
		description = "Trojan:Win32/Babar.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_02_0 = {43 00 3a 00 5c 00 4d 00 41 00 54 00 52 00 49 00 58 00 5c 00 74 00 6d 00 70 00 5c 00 [0-20] 2e 00 76 00 62 00 70 00 } //3
		$a_02_1 = {43 3a 5c 4d 41 54 52 49 58 5c 74 6d 70 5c [0-20] 2e 76 62 70 } //3
		$a_81_2 = {37 37 30 61 61 65 37 38 2d 66 32 36 66 2d 34 64 62 61 2d 61 38 32 39 2d 32 35 33 63 38 33 64 31 62 33 38 37 } //3 770aae78-f26f-4dba-a829-253c83d1b387
		$a_81_3 = {47 65 74 49 6e 73 74 61 6c 6c 44 65 74 61 69 6c 73 50 61 79 6c 6f 61 64 } //1 GetInstallDetailsPayload
		$a_81_4 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 DllCanUnloadNow
		$a_81_5 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_6 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllUnregisterServer
	condition:
		((#a_02_0  & 1)*3+(#a_02_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=10
 
}