
rule Ransom_Win32_FileCoder_GJN_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.GJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 77 00 62 00 65 00 6d 00 5c 00 57 00 4d 00 49 00 43 00 2e 00 65 00 78 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 } //1 cmd.exe /c C:\Windows\System32\wbem\WMIC.exe shadowcopy
		$a_01_1 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 } //1 SELECT * FROM Win32_ShadowCopy
		$a_80_2 = {43 4f 4e 54 49 5f 4c 4f 47 2e 74 78 74 } //CONTI_LOG.txt  1
		$a_80_3 = {72 65 61 64 6d 65 2e 74 78 74 } //readme.txt  1
		$a_01_4 = {44 45 43 52 59 50 54 5f 4e 4f 54 45 } //1 DECRYPT_NOTE
		$a_01_5 = {43 00 61 00 6e 00 27 00 74 00 20 00 77 00 72 00 69 00 74 00 65 00 20 00 6b 00 65 00 79 00 20 00 66 00 6f 00 72 00 20 00 66 00 69 00 6c 00 65 00 20 00 25 00 73 00 2e 00 20 00 47 00 65 00 74 00 4c 00 61 00 73 00 74 00 45 00 72 00 72 00 6f 00 72 00 20 00 3d 00 20 00 25 00 6c 00 75 00 } //1 Can't write key for file %s. GetLastError = %lu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}