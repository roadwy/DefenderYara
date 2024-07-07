
rule Backdoor_Win32_Bifrose_gen_C{
	meta:
		description = "Backdoor:Win32/Bifrose.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 09 00 06 00 00 "
		
	strings :
		$a_00_0 = {55 8b ec 56 33 f6 39 75 0c 7e 1b 8b 45 08 33 d2 8d 0c 06 8b c6 f7 75 14 8b 45 10 8a 04 02 30 01 46 3b 75 0c 7c e5 5e 5d } //9
		$a_03_1 = {50 89 b5 80 fa ff ff 89 75 e4 89 bd 78 fa ff ff c7 85 7c fa ff ff 90 01 04 c7 85 84 fa ff ff 90 01 04 ff d7 90 00 } //3
		$a_00_2 = {77 69 6e 73 2e 73 79 73 } //3 wins.sys
		$a_01_3 = {3c 4c 65 66 74 20 57 69 6e 64 6f 77 73 20 6b 65 79 20 44 4f 57 4e 3e } //1 <Left Windows key DOWN>
		$a_01_4 = {48 54 54 50 4d 61 69 6c 20 50 61 73 73 77 6f 72 64 32 } //1 HTTPMail Password2
		$a_01_5 = {4d 53 4e 20 45 78 70 6c 6f 72 65 72 20 53 69 67 6e 75 70 } //1 MSN Explorer Signup
	condition:
		((#a_00_0  & 1)*9+(#a_03_1  & 1)*3+(#a_00_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}