
rule Backdoor_Win32_Farfli_BR_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 48 52 30 63 44 6f 76 4c 7a 45 33 4d 69 34 79 4e 44 63 75 4d 6a 49 7a 4c 6a 45 7a 4d 44 6f 34 4f 54 63 31 4c 30 6c 43 62 33 68 49 5a 57 78 77 5a 58 49 75 5a 47 78 73 } //2 aHR0cDovLzE3Mi4yNDcuMjIzLjEzMDo4OTc1L0lCb3hIZWxwZXIuZGxs
		$a_01_1 = {61 48 52 30 63 44 6f 76 4c 7a 45 33 4d 69 34 79 4e 44 63 75 4d 6a 49 7a 4c 6a 45 7a 4d 44 6f 34 4f 54 63 31 4c 32 } //2 aHR0cDovLzE3Mi4yNDcuMjIzLjEzMDo4OTc1L2
		$a_01_2 = {62 61 6f 62 65 69 65 72 5c 44 6c 6c 31 5c 52 65 6c 65 61 73 65 5c 44 6c 6c 31 2e 70 64 62 } //2 baobeier\Dll1\Release\Dll1.pdb
		$a_01_3 = {55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 5c 49 42 6f 78 48 65 6c 70 65 72 2e 64 6c 6c } //2 Users\Public\Documents\\IBoxHelper.dll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}