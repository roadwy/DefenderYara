
rule Trojan_Win32_Stealer_MU_MTB{
	meta:
		description = "Trojan:Win32/Stealer.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 12 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 61 77 75 61 73 62 30 39 2e 74 6f 70 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 } //10 http://awuasb09.top/download.php
		$a_81_1 = {2f 69 6e 64 65 78 2e 70 68 70 } //1 /index.php
		$a_81_2 = {5c 5f 46 69 6c 65 73 5c 5f 41 6c 6c 50 61 73 73 77 6f 72 64 73 5f 6c 69 73 74 2e 74 78 74 } //1 \_Files\_AllPasswords_list.txt
		$a_81_3 = {5c 66 69 6c 65 73 5f 5c 70 61 73 73 77 6f 72 64 73 2e 74 78 74 } //1 \files_\passwords.txt
		$a_81_4 = {53 45 4c 45 43 54 20 6f 72 69 67 69 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //1 SELECT origin_url, username_value, password_value FROM logins
		$a_81_5 = {5c 5f 46 69 6c 65 73 5c 5f 41 6c 6c 43 6f 6f 6b 69 65 73 5f 6c 69 73 74 2e 74 78 74 } //1 \_Files\_AllCookies_list.txt
		$a_81_6 = {5c 5f 46 69 6c 65 73 5c 5f 43 6f 6f 6b 69 65 73 5c 67 6f 6f 67 6c 65 5f 63 68 72 6f 6d 65 5f 6e 65 77 2e 74 78 74 } //1 \_Files\_Cookies\google_chrome_new.txt
		$a_81_7 = {53 45 4c 45 43 54 20 68 6f 73 74 5f 6b 65 79 2c 20 70 61 74 68 2c 20 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 63 6f 6f 6b 69 65 73 } //1 SELECT host_key, path, name, encrypted_value FROM cookies
		$a_81_8 = {5c 5f 46 69 6c 65 73 5c 5f 41 6c 6c 5f 43 43 5f 6c 69 73 74 2e 74 78 74 } //1 \_Files\_All_CC_list.txt
		$a_81_9 = {53 45 4c 45 43 54 20 6e 61 6d 65 5f 6f 6e 5f 63 61 72 64 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 6d 6f 6e 74 68 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 79 65 61 72 2c 20 63 61 72 64 5f 6e 75 6d 62 65 72 5f 65 6e 63 72 79 70 74 65 64 20 46 52 4f 4d 20 63 72 65 64 69 74 5f 63 61 72 64 73 } //1 SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards
		$a_81_10 = {5c 5f 46 69 6c 65 73 5c 5f 41 6c 6c 46 6f 72 6d 73 5f 6c 69 73 74 2e 74 78 74 } //1 \_Files\_AllForms_list.txt
		$a_81_11 = {5c 6b 65 79 34 2e 64 62 } //1 \key4.db
		$a_81_12 = {5c 66 65 68 53 38 2e 74 6d 70 } //1 \fehS8.tmp
		$a_81_13 = {5c 66 69 6c 65 73 5f 5c 63 72 79 70 74 6f 63 75 72 72 65 6e 63 79 } //1 \files_\cryptocurrency
		$a_81_14 = {25 41 70 70 44 61 74 61 25 5c 50 65 67 61 73 } //1 %AppData%\Pegas
		$a_81_15 = {5c 5f 46 69 6c 65 73 5c 5f 57 61 6c 6c 65 74 } //1 \_Files\_Wallet
		$a_81_16 = {5c 5f 46 69 6c 65 73 5c 5f 53 63 72 65 65 6e 5f 44 65 73 6b 74 6f 70 2e 6a 70 65 67 } //1 \_Files\_Screen_Desktop.jpeg
		$a_81_17 = {5c 5f 46 69 6c 65 73 5c 5f 57 61 6c 6c 65 74 5c 45 6c 65 63 74 72 6f 6e 43 61 73 68 } //1 \_Files\_Wallet\ElectronCash
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1+(#a_81_17  & 1)*1) >=15
 
}