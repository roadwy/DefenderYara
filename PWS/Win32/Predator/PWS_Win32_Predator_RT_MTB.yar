
rule PWS_Win32_Predator_RT_MTB{
	meta:
		description = "PWS:Win32/Predator.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_01_0 = {6f 73 5f 63 72 79 70 74 } //1 os_crypt
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //1 encrypted_key
		$a_01_2 = {53 45 4c 45 43 54 20 6f 72 69 67 69 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //1 SELECT origin_url, username_value, password_value FROM logins
		$a_01_3 = {53 45 4c 45 43 54 20 68 6f 73 74 5f 6b 65 79 2c 20 70 61 74 68 2c 20 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 63 6f 6f 6b 69 65 73 } //1 SELECT host_key, path, name, encrypted_value FROM cookies
		$a_01_4 = {53 45 4c 45 43 54 20 6e 61 6d 65 5f 6f 6e 5f 63 61 72 64 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 6d 6f 6e 74 68 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 79 65 61 72 2c 20 63 61 72 64 5f 6e 75 6d 62 65 72 5f 65 6e 63 72 79 70 74 65 64 20 46 52 4f 4d 20 63 72 65 64 69 74 5f 63 61 72 64 73 } //1 SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards
		$a_01_5 = {55 6e 6d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //1 UnmapViewOfFile
		$a_00_6 = {5c 00 5f 00 46 00 69 00 6c 00 65 00 73 00 5c 00 5f 00 41 00 6c 00 6c 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 5f 00 6c 00 69 00 73 00 74 00 2e 00 74 00 78 00 74 00 } //10 \_Files\_AllPasswords_list.txt
		$a_00_7 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 65 00 73 00 6d 00 78 00 63 00 30 00 31 00 2e 00 74 00 6f 00 70 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2e 00 70 00 68 00 70 00 3f 00 66 00 69 00 6c 00 65 00 3d 00 6c 00 76 00 2e 00 65 00 78 00 65 00 } //10 http://esmxc01.top/download.php?file=lv.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*10+(#a_00_7  & 1)*10) >=24
 
}