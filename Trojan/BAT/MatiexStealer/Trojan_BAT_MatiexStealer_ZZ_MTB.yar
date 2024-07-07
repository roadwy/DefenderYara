
rule Trojan_BAT_MatiexStealer_ZZ_MTB{
	meta:
		description = "Trojan:BAT/MatiexStealer.ZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 19 00 00 "
		
	strings :
		$a_01_0 = {52 65 63 6f 76 65 72 65 64 50 53 57 44 } //1 RecoveredPSWD
		$a_01_1 = {67 65 74 5f 74 69 6d 65 50 61 73 73 77 6f 72 64 43 68 61 6e 67 65 64 } //1 get_timePasswordChanged
		$a_01_2 = {73 65 74 5f 74 69 6d 65 50 61 73 73 77 6f 72 64 43 68 61 6e 67 65 64 } //1 set_timePasswordChanged
		$a_01_3 = {67 65 74 5f 70 61 73 73 77 6f 72 64 46 69 65 6c 64 } //1 get_passwordField
		$a_01_4 = {73 65 74 5f 70 61 73 73 77 6f 72 64 46 69 65 6c 64 } //1 set_passwordField
		$a_01_5 = {67 65 74 5f 75 73 65 72 6e 61 6d 65 46 69 65 6c 64 } //1 get_usernameField
		$a_01_6 = {73 65 74 5f 75 73 65 72 6e 61 6d 65 46 69 65 6c 64 } //1 set_usernameField
		$a_01_7 = {67 65 74 5f 50 61 73 73 77 6f 72 64 } //1 get_Password
		$a_01_8 = {73 65 74 5f 50 61 73 73 77 6f 72 64 } //1 set_Password
		$a_01_9 = {67 65 74 5f 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //1 get_encryptedPassword
		$a_01_10 = {73 65 74 5f 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //1 set_encryptedPassword
		$a_01_11 = {67 65 74 5f 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 } //1 get_encryptedUsername
		$a_01_12 = {73 65 74 5f 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 } //1 set_encryptedUsername
		$a_01_13 = {43 72 65 64 65 6e 74 69 61 6c 4d 6f 64 65 6c } //1 CredentialModel
		$a_01_14 = {46 46 4c 6f 67 69 6e 73 } //1 FFLogins
		$a_01_15 = {67 65 74 5f 6c 6f 67 69 6e 73 } //1 get_logins
		$a_01_16 = {73 65 74 5f 6c 6f 67 69 6e 73 } //1 set_logins
		$a_01_17 = {50 4b 31 31 53 44 52 5f 44 65 63 72 79 70 74 } //1 PK11SDR_Decrypt
		$a_01_18 = {4f 72 67 69 6e 61 6c 5f 50 6f 73 74 42 6f 78 } //1 Orginal_PostBox
		$a_01_19 = {4f 72 67 69 6e 61 6c 5f 46 69 72 65 46 6f 78 } //1 Orginal_FireFox
		$a_01_20 = {4f 72 67 69 6e 61 6c 5f 43 79 62 65 72 46 6f 78 } //1 Orginal_CyberFox
		$a_01_21 = {4f 72 67 69 6e 61 6c 5f 57 61 74 65 72 46 6f 78 } //1 Orginal_WaterFox
		$a_01_22 = {4f 72 67 69 6e 61 6c 5f 53 65 61 4d 6f 6e 6b 65 79 } //1 Orginal_SeaMonkey
		$a_00_23 = {6c 00 6f 00 67 00 69 00 6e 00 73 00 2e 00 6a 00 73 00 6f 00 6e 00 } //1 logins.json
		$a_00_24 = {4d 00 61 00 74 00 69 00 65 00 78 00 } //1 Matiex
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_00_23  & 1)*1+(#a_00_24  & 1)*1) >=25
 
}