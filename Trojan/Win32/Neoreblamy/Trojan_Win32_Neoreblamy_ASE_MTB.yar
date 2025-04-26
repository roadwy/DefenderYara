
rule Trojan_Win32_Neoreblamy_ASE_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 67 4d 42 4e 69 76 6a 48 59 75 70 6f 67 62 64 73 41 4d 4b 69 6c 4e 68 52 77 59 61 6e 68 61 54 } //1 IgMBNivjHYupogbdsAMKilNhRwYanhaT
		$a_01_1 = {67 53 67 51 56 65 52 4d 46 46 65 46 67 4c 51 4e 4c 7a 47 67 6c 74 6d 51 42 4c 4d } //1 gSgQVeRMFFeFgLQNLzGgltmQBLM
		$a_01_2 = {4b 42 64 63 73 72 79 79 49 56 47 55 67 46 6e 71 48 6f 61 4d 6b 43 58 72 59 7a 44 59 51 6e 44 64 4a 4a 78 } //1 KBdcsryyIVGUgFnqHoaMkCXrYzDYQnDdJJx
		$a_01_3 = {61 61 49 6d 52 4c 79 6f 6e 48 43 70 43 71 55 70 62 6b 58 54 50 78 43 76 6e } //1 aaImRLyonHCpCqUpbkXTPxCvn
		$a_01_4 = {43 69 54 58 66 75 55 5a 59 64 62 50 58 6d 4e 6e 61 65 4d 44 45 4c 64 61 6a 6a 69 4d } //1 CiTXfuUZYdbPXmNnaeMDELdajjiM
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}