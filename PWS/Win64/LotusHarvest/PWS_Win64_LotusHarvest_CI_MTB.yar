
rule PWS_Win64_LotusHarvest_CI_MTB{
	meta:
		description = "PWS:Win64/LotusHarvest.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_01_0 = {64 65 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //2 decryptedPassword
		$a_01_1 = {63 6f 6d 70 75 74 65 72 4e 61 6d 65 } //2 computerName
		$a_01_2 = {75 73 65 72 4e 61 6d 65 } //2 userName
		$a_01_3 = {53 45 4c 45 43 54 20 6f 72 69 67 69 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 2c 20 64 61 74 65 5f 63 72 65 61 74 65 64 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //2 SELECT origin_url, username_value, password_value, date_created FROM logins
		$a_01_4 = {43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 } //2 Chrome\User Data
		$a_01_5 = {45 64 67 65 5c 55 73 65 72 20 44 61 74 61 } //2 Edge\User Data
		$a_01_6 = {63 6f 6d 70 75 74 65 72 5f 6e 61 6d 65 22 3a 22 25 73 22 2c 22 75 73 65 72 5f 6e 61 6d 65 22 3a 22 25 73 22 2c 22 64 61 74 61 22 3a } //2 computer_name":"%s","user_name":"%s","data":
		$a_01_7 = {74 79 70 65 22 3a 22 70 61 73 73 77 6f 72 64 73 22 2c 22 65 6e 74 72 69 65 73 22 } //2 type":"passwords","entries"
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=16
 
}