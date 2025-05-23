
rule Ransom_Win32_Blulock_A{
	meta:
		description = "Ransom:Win32/Blulock.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 4c 6f 63 6b 44 6c 6c 2e 64 6c 6c 00 } //1
		$a_01_1 = {54 61 73 6b 4d 61 6e 61 67 65 72 5f 45 6e 61 62 6c 65 5f 44 69 73 61 62 6c 65 00 } //1
		$a_01_2 = {54 61 73 6b 53 77 69 74 63 68 69 6e 67 5f 45 6e 61 62 6c 65 5f 44 69 73 61 62 6c 65 00 } //1
		$a_01_3 = {41 6c 74 54 61 62 32 5f 45 6e 61 62 6c 65 5f 44 69 73 61 62 6c 65 00 } //1
		$a_00_4 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 62 6c 75 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}