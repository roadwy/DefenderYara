
rule Ransom_Win32_Embargo_DA_MTB{
	meta:
		description = "Ransom:Win32/Embargo.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {65 00 6d 00 62 00 61 00 72 00 67 00 6f 00 3a 00 3a 00 [0-0f] 3a 00 3a 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 } //1
		$a_03_1 = {65 6d 62 61 72 67 6f 3a 3a [0-0f] 3a 3a 65 6e 63 72 79 70 74 } //1
		$a_81_2 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 2f 71 2f 63 62 63 64 65 64 69 74 2f 73 65 74 7b 64 65 66 61 75 6c 74 7d 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 6e 6f } //1 C:\Windows\System32\cmd.exe/q/cbcdedit/set{default}recoveryenabledno
		$a_81_3 = {44 65 6c 65 74 65 64 20 20 73 68 61 64 6f 77 73 } //1 Deleted  shadows
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=3
 
}