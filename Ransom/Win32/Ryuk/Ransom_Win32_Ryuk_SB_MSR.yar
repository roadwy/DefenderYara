
rule Ransom_Win32_Ryuk_SB_MSR{
	meta:
		description = "Ransom:Win32/Ryuk.SB!MSR,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {6f 70 65 72 61 74 69 6f 6e 5f 77 6f 75 6c 64 5f 62 6c 6f 63 6b } //1 operation_would_block
		$a_01_1 = {6f 77 6e 65 72 20 64 65 61 64 } //1 owner dead
		$a_01_2 = {4d 59 43 4f 44 45 } //1 MYCODE
		$a_01_3 = {45 75 72 70 65 61 6e 73 20 63 72 75 63 69 66 69 78 69 6f 6e } //1 Eurpeans crucifixion
		$a_01_4 = {44 00 58 00 42 00 41 00 52 00 44 00 41 00 54 00 45 00 43 00 4f 00 4d 00 42 00 4f 00 } //1 DXBARDATECOMBO
		$a_01_5 = {53 00 50 00 5f 00 53 00 48 00 41 00 44 00 4f 00 57 00 32 00 31 00 } //1 SP_SHADOW21
		$a_01_6 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 57 } //1 FindFirstFileW
		$a_01_7 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 57 } //1 FindNextFileW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}