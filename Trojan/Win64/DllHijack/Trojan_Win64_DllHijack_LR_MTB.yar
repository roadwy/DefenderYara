
rule Trojan_Win64_DllHijack_LR_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.LR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 05 00 00 "
		
	strings :
		$a_03_0 = {48 8d 4c 24 20 4c 3b ca 66 89 7c 24 20 f3 0f 7f 44 24 30 49 0f 42 d1 48 83 7c 24 58 08 4c 8d 4c 24 40 4c 0f 43 4c 24 40 48 83 fa 07 77 ?? 48 8d 1c 12 48 89 54 24 30 4c 8b c3 49 8b d1 } //10
		$a_81_1 = {25 25 53 79 73 74 65 6d 52 6f 6f 74 25 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 22 25 73 22 } //1 %%SystemRoot%%\System32\svchost.exe -k "%s"
		$a_81_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 4d 75 73 69 63 5c 53 65 72 76 69 63 65 2e 64 6c 6c } //2 C:\Users\Public\Music\Service.dll
		$a_81_3 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 4d 75 73 69 63 5c 61 74 6c 2e 69 6e 69 } //3 C:\Users\Public\Music\atl.ini
		$a_81_4 = {53 65 72 76 69 63 65 44 6c 6c } //4 ServiceDll
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*2+(#a_81_3  & 1)*3+(#a_81_4  & 1)*4) >=20
 
}