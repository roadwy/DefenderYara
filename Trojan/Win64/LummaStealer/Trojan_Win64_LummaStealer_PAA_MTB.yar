
rule Trojan_Win64_LummaStealer_PAA_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {5b 2b 5d 20 4c 75 6d 6d 61 43 32 20 53 74 65 61 6c 65 72 20 73 74 61 72 74 65 64 } //1 [+] LummaC2 Stealer started
		$a_81_1 = {6c 75 6d 6d 61 5f 64 65 62 75 67 2e 6c 6f 67 } //1 lumma_debug.log
		$a_81_2 = {37 39 37 34 36 39 32 36 37 35 3a 41 41 48 66 59 41 7a 61 51 42 41 44 39 6c 4f 4f 33 68 7a 76 54 67 43 4a 4b 72 34 51 66 35 31 53 6d 73 41 } //1 7974692675:AAHfYAzaQBAD9lOO3hzvTgCJKr4Qf51SmsA
		$a_81_3 = {53 45 4c 45 43 54 20 68 6f 73 74 5f 6b 65 79 2c 20 6e 61 6d 65 2c 20 70 61 74 68 2c 20 65 6e 63 72 79 70 74 65 64 5f 76 61 6c 75 65 2c 20 65 78 70 69 72 65 73 5f 75 74 63 20 46 52 4f 4d 20 63 6f 6f 6b 69 65 73 } //1 SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies
		$a_81_4 = {53 45 4c 45 43 54 20 6e 61 6d 65 5f 6f 6e 5f 63 61 72 64 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 6d 6f 6e 74 68 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 79 65 61 72 2c 20 63 61 72 64 5f 6e 75 6d 62 65 72 5f 65 6e 63 72 79 70 74 65 64 20 46 52 4f 4d 20 63 72 65 64 69 74 5f 63 61 72 64 73 } //1 SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards
		$a_81_5 = {53 45 4c 45 43 54 20 6f 72 69 67 69 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //1 SELECT origin_url, username_value, password_value FROM logins
		$a_81_6 = {61 66 62 63 62 6a 70 62 70 66 61 64 6c 6b 6d 68 6d 63 6c 68 6b 65 65 6f 64 6d 61 6d 63 66 6c 63 } //1 afbcbjpbpfadlkmhmclhkeeodmamcflc
		$a_81_7 = {68 70 67 6c 66 68 67 66 6e 68 62 67 70 6a 64 65 6e 6a 67 6d 64 67 6f 65 69 61 70 70 61 66 6c 6e } //1 hpglfhgfnhbgpjdenjgmdgoeiappafln
		$a_81_8 = {6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //1 logins.json
		$a_81_9 = {5c 6b 65 79 33 2e 64 62 } //1 \key3.db
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}