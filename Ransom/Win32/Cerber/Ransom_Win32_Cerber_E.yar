
rule Ransom_Win32_Cerber_E{
	meta:
		description = "Ransom:Win32/Cerber.E,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 05 00 00 "
		
	strings :
		$a_01_0 = {c7 03 43 72 62 52 } //10
		$a_01_1 = {4a 4a 4a 4a 4b 52 4a 4a 4a 4a 4f 4c 4a 4a 4a 4a 4a 4a 4a 4a 55 45 40 4a 4a 4a 45 59 4d 46 4a 5d 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 61 63 67 4e 4a 4a 6b 6d 4a 4a 45 6d 4a 4a 44 45 4a 4a } //10 JJJJKRJJJJOLJJJJJJJJUE@JJJEYMFJ]JJJJJJJJJJJJJJacgNJJkmJJEmJJDEJJ
		$a_01_2 = {40 40 40 40 41 49 40 40 40 40 4c 42 40 40 40 40 40 40 40 40 4f 44 53 40 40 40 44 57 43 5c 40 } //10 @@@@AI@@@@LB@@@@@@@@ODS@@@DWC\@
		$a_01_3 = {4e 74 51 75 65 72 79 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //10 NtQueryVirtualMemory
		$a_01_4 = {43 72 79 70 74 44 65 63 6f 64 65 4f 62 6a 65 63 74 45 78 } //10 CryptDecodeObjectEx
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10) >=50
 
}