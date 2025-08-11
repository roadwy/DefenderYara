
rule Trojan_Win64_Dacic_C_MTB{
	meta:
		description = "Trojan:Win64/Dacic.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 09 00 00 "
		
	strings :
		$a_01_0 = {61 70 70 5f 62 6f 75 6e 64 5f 65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //2 app_bound_encrypted_key
		$a_01_1 = {63 68 72 6f 6d 65 5f 61 70 70 62 6f 75 6e 64 5f 6b 65 79 2e 74 78 74 } //2 chrome_appbound_key.txt
		$a_01_2 = {53 45 4c 45 43 54 20 68 6f 73 74 5f 6b 65 79 2c 20 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 63 6f 6f 6b 69 65 73 3b } //2 SELECT host_key, name, encrypted_value FROM cookies;
		$a_01_3 = {53 45 4c 45 43 54 20 6f 72 69 67 69 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 3b } //2 SELECT origin_url, username_value, password_value FROM logins;
		$a_01_4 = {53 45 4c 45 43 54 20 67 75 69 64 2c 20 6e 61 6d 65 5f 6f 6e 5f 63 61 72 64 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 6d 6f 6e 74 68 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 79 65 61 72 2c 20 63 61 72 64 5f 6e 75 6d 62 65 72 5f 65 6e 63 72 79 70 74 65 64 20 46 52 4f 4d 20 63 72 65 64 69 74 5f 63 61 72 64 73 3b } //2 SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards;
		$a_01_5 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //1 ReflectiveLoader
		$a_01_6 = {55 73 65 72 20 44 61 74 61 } //1 User Data
		$a_01_7 = {4c 6f 67 69 6e 20 44 61 74 61 } //1 Login Data
		$a_01_8 = {63 68 72 6f 6d 65 5f 64 65 63 72 79 70 74 2e 6c 6f 67 } //1 chrome_decrypt.log
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=14
 
}