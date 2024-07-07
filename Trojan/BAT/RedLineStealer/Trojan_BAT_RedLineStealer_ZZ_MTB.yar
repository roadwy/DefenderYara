
rule Trojan_BAT_RedLineStealer_ZZ_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.ZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 16 00 00 "
		
	strings :
		$a_01_0 = {44 65 74 65 63 74 43 72 65 64 69 74 43 61 72 64 54 79 70 65 } //1 DetectCreditCardType
		$a_01_1 = {50 61 72 73 65 42 72 6f 77 73 65 72 73 } //1 ParseBrowsers
		$a_01_2 = {43 72 65 64 65 6e 74 69 61 6c 73 53 74 61 67 65 } //1 CredentialsStage
		$a_01_3 = {52 65 64 4c 69 6e 65 2e 52 65 62 75 72 6e 2e 4d 6f 64 65 6c 73 } //1 RedLine.Reburn.Models
		$a_01_4 = {67 65 74 5f 47 72 61 62 56 50 4e } //1 get_GrabVPN
		$a_01_5 = {73 65 74 5f 47 72 61 62 56 50 4e } //1 set_GrabVPN
		$a_01_6 = {67 65 74 5f 4e 6f 72 64 56 50 4e } //1 get_NordVPN
		$a_01_7 = {73 65 74 5f 4e 6f 72 64 56 50 4e } //1 set_NordVPN
		$a_01_8 = {67 65 74 5f 4f 70 65 6e 56 50 4e } //1 get_OpenVPN
		$a_01_9 = {73 65 74 5f 4f 70 65 6e 56 50 4e } //1 set_OpenVPN
		$a_01_10 = {67 65 74 5f 50 72 6f 74 6f 6e 56 50 4e } //1 get_ProtonVPN
		$a_01_11 = {73 65 74 5f 50 72 6f 74 6f 6e 56 50 4e } //1 set_ProtonVPN
		$a_01_12 = {67 65 74 5f 53 65 73 73 69 6f 6e 49 64 } //1 get_SessionId
		$a_01_13 = {67 65 74 5f 70 61 73 73 77 6f 72 64 46 69 65 6c 64 } //1 get_passwordField
		$a_01_14 = {73 65 74 5f 70 61 73 73 77 6f 72 64 46 69 65 6c 64 } //1 set_passwordField
		$a_01_15 = {67 65 74 5f 75 73 65 72 6e 61 6d 65 46 69 65 6c 64 } //1 get_usernameField
		$a_01_16 = {73 65 74 5f 75 73 65 72 6e 61 6d 65 46 69 65 6c 64 } //1 set_usernameField
		$a_01_17 = {52 65 64 4c 69 6e 65 2e 52 65 62 75 72 6e 2e 44 61 74 61 } //1 RedLine.Reburn.Data
		$a_01_18 = {67 65 74 5f 57 61 6c 6c 65 74 44 69 72 } //1 get_WalletDir
		$a_01_19 = {73 65 74 5f 57 61 6c 6c 65 74 44 69 72 } //1 set_WalletDir
		$a_01_20 = {67 65 74 5f 43 72 65 64 69 74 43 61 72 64 73 } //1 get_CreditCards
		$a_01_21 = {73 65 74 5f 43 72 65 64 69 74 43 61 72 64 73 } //1 set_CreditCards
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1) >=22
 
}