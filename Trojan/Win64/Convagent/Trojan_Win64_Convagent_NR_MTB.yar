
rule Trojan_Win64_Convagent_NR_MTB{
	meta:
		description = "Trojan:Win64/Convagent.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 c7 85 b8 00 00 00 1f 00 00 00 0f 10 05 a3 bf 02 00 0f 11 00 f2 0f 10 05 a8 bf 02 00 f2 0f 11 40 10 0f b7 0d a4 bf 02 00 66 89 48 18 0f b6 0d 9b bf 02 00 88 48 1a c6 40 1b 00 80 3d 33 2c 04 00 00 0f 84 93 00 00 00 } //2
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 20 6f 66 20 44 4c 4c 20 70 61 74 68 20 74 6f 20 72 65 6d 6f 74 65 20 61 64 64 72 65 73 73 } //1 WriteProcessMemory of DLL path to remote address
		$a_01_2 = {44 4c 4c 20 69 6e 6a 65 63 74 65 64 } //1 DLL injected
		$a_01_3 = {44 4c 4c 20 64 65 63 72 79 70 74 69 6f 6e 20 74 61 73 6b 73 20 74 6f 20 63 6f 6d 70 6c 65 74 65 } //1 DLL decryption tasks to complete
		$a_01_4 = {63 00 68 00 72 00 6f 00 6d 00 65 00 5f 00 69 00 6e 00 6a 00 65 00 63 00 74 00 2e 00 65 00 78 00 65 00 } //1 chrome_inject.exe
		$a_01_5 = {63 00 68 00 72 00 6f 00 6d 00 65 00 5f 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 2e 00 64 00 6c 00 6c 00 } //1 chrome_decrypt.dll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}