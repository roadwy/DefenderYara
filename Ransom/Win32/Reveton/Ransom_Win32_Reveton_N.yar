
rule Ransom_Win32_Reveton_N{
	meta:
		description = "Ransom:Win32/Reveton.N,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {64 8b 05 30 00 00 00 8b 40 0c 8b 40 0c 8b 00 3b 70 18 75 f9 8b 30 8b 58 04 89 33 8b 70 04 8b 18 89 73 04 8d 40 08 8b 30 8b 58 04 89 33 8b 70 04 8b 18 89 73 04 } //10
		$a_01_1 = {4a 69 6d 6d 4d 6f 6e 73 74 65 72 4e 65 77 5c 53 65 72 76 65 72 57 69 6e 6c 6f 63 6b } //1 JimmMonsterNew\ServerWinlock
		$a_01_2 = {72 75 6e 63 74 66 2e 6c 6e 6b 00 } //1
		$a_01_3 = {00 4c 6f 63 6b 2e 64 6c 6c } //1
		$a_03_4 = {43 6f 75 6e 74 72 79 3a 90 01 0c 43 69 74 79 3a 90 01 0b 49 50 3a 90 00 } //1
		$a_01_5 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 53 68 65 6c 6c } //1 CurrentVersion\Winlogon\Shell
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=13
 
}