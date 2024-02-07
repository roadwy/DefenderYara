
rule Trojan_Win32_DarkCloudStealer_SE_MTB{
	meta:
		description = "Trojan:Win32/DarkCloudStealer.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {73 69 74 65 6d 61 6e 61 67 65 72 2e 78 6d 6c } //01 00  sitemanager.xml
		$a_81_1 = {53 45 4c 45 43 54 20 6e 61 6d 65 5f 6f 6e 5f 63 61 72 64 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 6d 6f 6e 74 68 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 79 65 61 72 2c 20 63 61 72 64 5f 6e 75 6d 62 65 72 5f 65 6e 63 72 79 70 74 65 64 20 20 46 52 4f 4d 20 63 72 65 64 69 74 5f 63 61 72 64 73 } //01 00  SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted  FROM credit_cards
		$a_81_2 = {53 45 4c 45 43 54 20 6f 72 69 67 69 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 2c 20 6c 65 6e 67 74 68 28 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 29 20 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //01 00  SELECT origin_url, username_value, password_value, length(password_value)  FROM logins
		$a_81_3 = {3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 44 41 52 4b 43 4c 4f 55 44 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d } //01 00  ===============DARKCLOUD===============
		$a_81_4 = {54 68 75 6e 64 65 72 42 69 72 64 43 6f 6e 74 61 63 74 73 2e 74 78 74 } //01 00  ThunderBirdContacts.txt
		$a_81_5 = {4d 61 69 6c 43 6f 6e 74 61 63 74 73 2e 74 78 74 } //00 00  MailContacts.txt
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_DarkCloudStealer_SE_MTB_2{
	meta:
		description = "Trojan:Win32/DarkCloudStealer.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {3d 3d 44 41 52 4b 43 4c 4f 55 44 3d 3d } //01 00  ==DARKCLOUD==
		$a_81_1 = {4c 6f 67 66 6f 72 6d 75 6c 61 72 69 73 65 72 62 45 44 53 58 52 72 4e 51 55 67 4e 66 6e 55 61 73 52 55 59 5a 6c 4f 4a 71 77 67 61 6c 61 63 74 69 63 } //01 00  LogformulariserbEDSXRrNQUgNfnUasRUYZlOJqwgalactic
		$a_81_2 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 46 6f 78 6d 61 69 6c 2e 75 72 6c 2e 6d 61 69 6c 74 6f 5c 53 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00  SOFTWARE\Classes\Foxmail.url.mailto\Shell\open\command
		$a_81_3 = {61 63 63 6f 75 6e 74 73 2e 78 6d 6c } //01 00  accounts.xml
		$a_81_4 = {53 45 4c 45 43 54 20 6e 61 6d 65 5f 6f 6e 5f 63 61 72 64 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 6d 6f 6e 74 68 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 79 65 61 72 2c 20 63 61 72 64 5f 6e 75 6d 62 65 72 5f 65 6e 63 72 79 70 74 65 64 20 20 46 52 4f 4d 20 63 72 65 64 69 74 5f 63 61 72 64 73 } //01 00  SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted  FROM credit_cards
		$a_81_5 = {53 45 4c 45 43 54 20 6f 72 69 67 69 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //01 00  SELECT origin_url, username_value, password_value  FROM logins
		$a_81_6 = {53 45 4c 45 43 54 20 65 78 70 69 72 79 2c 20 68 6f 73 74 2c 20 6e 61 6d 65 2c 20 70 61 74 68 2c 20 76 61 6c 75 65 20 20 46 52 4f 4d 20 6d 6f 7a 5f 63 6f 6f 6b 69 65 73 } //00 00  SELECT expiry, host, name, path, value  FROM moz_cookies
	condition:
		any of ($a_*)
 
}