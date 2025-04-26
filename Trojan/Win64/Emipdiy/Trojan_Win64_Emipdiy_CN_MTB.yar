
rule Trojan_Win64_Emipdiy_CN_MTB{
	meta:
		description = "Trojan:Win64/Emipdiy.CN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 64 72 41 64 64 78 36 34 2e 64 6c 6c } //3 LdrAddx64.dll
		$a_01_1 = {5a 00 3a 00 5c 00 68 00 6f 00 6f 00 6b 00 65 00 72 00 32 00 } //3 Z:\hooker2
		$a_01_2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 6d 79 5f 61 70 70 6c 69 63 61 74 69 6f 6e 5f 70 61 74 68 2c 20 50 72 6f 63 65 73 73 4c 6f 61 64 } //3 rundll32.exe my_application_path, ProcessLoad
		$a_01_3 = {5c 57 69 6e 64 6f 77 73 20 4d 61 69 6c 5c 77 61 62 2e 65 78 65 } //3 \Windows Mail\wab.exe
		$a_01_4 = {43 6f 53 65 74 50 72 6f 78 79 42 6c 61 6e 6b 65 74 } //3 CoSetProxyBlanket
		$a_01_5 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d 50 72 6f 64 75 63 74 } //3 SELECT * FROM Win32_ComputerSystemProduct
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3) >=18
 
}