
rule Trojan_Win64_PrivateLoader_BZ_MTB{
	meta:
		description = "Trojan:Win64/PrivateLoader.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_81_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 65 70 20 42 79 70 61 73 73 20 2d 63 20 22 20 24 72 65 73 70 6f 6e 73 65 20 3d 20 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 } //1 powershell -NoProfile -ep Bypass -c " $response = Invoke-WebRequest -Uri
		$a_03_1 = {68 00 74 74 00 70 00 3a 00 2f 00 2f 00 [0-0f] 2f 00 56 00 43 00 2f 00 54 00 68 00 65 00 2f 00 53 00 65 00 74 00 2e 00 70 00 68 00 70 00 } //1
		$a_03_2 = {68 74 74 70 3a 2f 2f [0-0f] 2f 56 43 2f 54 68 65 2f 53 65 74 2e 70 68 70 } //1
		$a_81_3 = {4e 6f 74 20 46 6f 75 6e 64 20 41 6e 74 69 56 69 72 75 73 } //1 Not Found AntiVirus
		$a_81_4 = {4c 4f 41 44 5f 45 58 45 2e 70 64 62 } //1 LOAD_EXE.pdb
		$a_81_5 = {43 3a 5c 53 62 69 65 44 6c 6c 2e 64 6c 6c } //1 C:\SbieDll.dll
		$a_81_6 = {3c 44 4c 4c 5f 49 4e 4a 45 43 54 3e } //1 <DLL_INJECT>
		$a_81_7 = {3c 45 58 45 5f 49 4e 4a 45 43 54 5f 57 49 4e 4c 4f 47 4f 4e 3e } //1 <EXE_INJECT_WINLOGON>
	condition:
		((#a_81_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=7
 
}