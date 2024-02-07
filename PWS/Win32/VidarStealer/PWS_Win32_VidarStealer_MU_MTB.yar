
rule PWS_Win32_VidarStealer_MU_MTB{
	meta:
		description = "PWS:Win32/VidarStealer.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0c 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 5c 42 43 52 59 50 54 2e 44 4c 4c } //01 00  C:\\BCRYPT.DLL
		$a_81_1 = {43 3a 5c 49 4e 54 45 52 4e 41 4c 5c 52 45 4d 4f 54 45 2e 45 58 45 } //01 00  C:\INTERNAL\REMOTE.EXE
		$a_81_2 = {70 61 73 73 77 6f 72 64 73 2e 74 78 74 } //01 00  passwords.txt
		$a_81_3 = {53 45 4c 45 43 54 20 6e 61 6d 65 5f 6f 6e 5f 63 61 72 64 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 6d 6f 6e 74 68 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 79 65 61 72 2c 20 63 61 72 64 5f 6e 75 6d 62 65 72 5f 65 6e 63 72 79 70 74 65 64 20 46 52 4f 4d 20 63 72 65 64 69 74 5f 63 61 72 64 73 } //01 00  SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards
		$a_81_4 = {5c 5c 73 69 67 6e 6f 6e 73 2e 73 71 6c 69 74 65 } //01 00  \\signons.sqlite
		$a_81_5 = {66 6f 72 6d 53 75 62 6d 69 74 55 52 4c } //01 00  formSubmitURL
		$a_81_6 = {72 65 63 65 6e 74 73 65 72 76 65 72 73 2e 78 6d 6c } //01 00  recentservers.xml
		$a_81_7 = {5c 5c 4e 69 63 68 72 6f 6d 65 5c 5c 55 73 65 72 20 44 61 74 61 5c 5c } //01 00  \\Nichrome\\User Data\\
		$a_81_8 = {5c 5c 45 70 69 63 20 50 72 69 76 61 63 79 20 42 72 6f 77 73 65 72 5c 5c 55 73 65 72 20 44 61 74 61 5c 5c } //01 00  \\Epic Privacy Browser\\User Data\\
		$a_81_9 = {5c 5c 62 72 61 76 65 5c 5c } //01 00  \\brave\\
		$a_81_10 = {43 6f 6f 6b 69 65 73 5c 5c 49 45 5f 43 6f 6f 6b 69 65 73 2e 74 78 74 } //01 00  Cookies\\IE_Cookies.txt
		$a_81_11 = {66 69 6c 65 73 5c 6f 75 74 6c 6f 6f 6b 2e 74 78 74 66 69 6c 65 73 5c 5c 6f 75 74 6c 6f 6f 6b 2e 74 78 74 } //00 00  files\outlook.txtfiles\\outlook.txt
	condition:
		any of ($a_*)
 
}