
rule Backdoor_Win32_PdfSider_C_MTB{
	meta:
		description = "Backdoor:Win32/PdfSider.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 4f 4d 50 55 54 45 52 4e 41 4d 45 } //2 COMPUTERNAME
		$a_01_1 = {55 53 45 52 4e 41 4d 45 } //2 USERNAME
		$a_01_2 = {6c 6f 67 67 65 72 20 77 69 74 68 20 6e 61 6d 65 20 27 63 6f 6e 73 6f 6c 65 27 20 61 6c 72 65 61 64 79 20 65 78 69 73 74 73 } //2 logger with name 'console' already exists
		$a_01_3 = {61 65 73 5f 64 65 63 72 79 70 74 } //2 aes_decrypt
		$a_01_4 = {7b 22 6e 61 6d 65 22 3a 20 22 25 73 22 2c 20 22 62 75 69 6c 64 5f 64 61 74 65 22 3a 20 22 25 73 20 25 73 22 2c 20 22 61 72 63 68 22 3a 20 22 77 69 6e 64 6f 77 73 22 2c 20 22 75 73 65 72 6e 61 6d 65 22 3a 20 22 25 73 22 2c 20 22 70 69 64 22 3a 20 22 25 64 22 20 7d } //2 {"name": "%s", "build_date": "%s %s", "arch": "windows", "username": "%s", "pid": "%d" }
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}