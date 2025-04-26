
rule Ransom_Win32_Fonix_MB_MTB{
	meta:
		description = "Ransom:Win32/Fonix.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 50 68 6f 65 6e 69 78 5c 44 6f 77 6e 6c 6f 61 64 73 5c 63 72 79 70 74 6f 70 70 38 30 30 } //1 C:\Users\Phoenix\Downloads\cryptopp800
		$a_01_1 = {4c 6f 63 6b 20 61 6c 72 65 61 64 79 20 74 61 6b 65 6e } //1 Lock already taken
		$a_01_2 = {50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 20 20 20 2f 76 20 4e 6f 52 75 6e 20 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 20 2f 66 } //1 Policies\Explorer   /v NoRun  /t REG_DWORD /d 0 /f
		$a_01_3 = {22 73 74 61 74 75 73 22 3a 22 43 6f 6d 70 6c 65 74 65 22 7d } //1 "status":"Complete"}
		$a_01_4 = {45 6e 64 20 2d 20 47 6f 6f 64 4c 75 63 6b } //1 End - GoodLuck
		$a_00_5 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 20 00 43 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 64 00 } //1 Encryption Completed
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}