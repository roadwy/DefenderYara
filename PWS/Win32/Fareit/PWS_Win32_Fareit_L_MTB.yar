
rule PWS_Win32_Fareit_L_MTB{
	meta:
		description = "PWS:Win32/Fareit.L!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 73 00 5f 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 2e 00 6c 00 6f 00 67 00 } //1 wbrowsers_passwords.log
		$a_01_1 = {25 73 5c 25 73 50 61 73 73 77 6f 72 64 73 2e 6c 6f 67 } //1 %s\%sPasswords.log
		$a_01_2 = {53 45 4c 45 43 54 20 6f 72 69 67 69 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //1 SELECT origin_url, username_value, password_value FROM logins
		$a_01_3 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3a 00 25 00 6c 00 73 00 } //1 password:%ls
		$a_01_4 = {66 69 6c 65 25 64 2e 65 78 65 } //1 file%d.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}