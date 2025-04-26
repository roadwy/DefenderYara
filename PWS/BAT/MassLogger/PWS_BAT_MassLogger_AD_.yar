
rule PWS_BAT_MassLogger_AD_{
	meta:
		description = "PWS:BAT/MassLogger.AD!!MassLogger.AD!MTB,SIGNATURE_TYPE_ARHSTR_EXT,15 00 15 00 15 00 00 "
		
	strings :
		$a_81_0 = {47 65 74 43 72 65 64 65 6e 74 69 61 6c 73 } //1 GetCredentials
		$a_81_1 = {5f 66 6f 72 6d 53 75 62 6d 69 74 55 52 4c } //1 _formSubmitURL
		$a_81_2 = {5f 41 64 61 70 74 65 72 52 41 4d } //1 _AdapterRAM
		$a_81_3 = {5f 47 72 61 62 56 50 4e } //1 _GrabVPN
		$a_81_4 = {5f 4e 6f 72 64 56 50 4e } //1 _NordVPN
		$a_81_5 = {5f 4f 70 65 6e 56 50 4e } //1 _OpenVPN
		$a_81_6 = {5f 50 72 6f 74 6f 6e 56 50 4e } //1 _ProtonVPN
		$a_81_7 = {52 4d 5f 50 52 4f 43 45 53 53 5f 49 4e 46 4f } //1 RM_PROCESS_INFO
		$a_81_8 = {5f 42 6c 61 63 6b 6c 69 73 74 65 64 49 50 } //1 _BlacklistedIP
		$a_81_9 = {5f 47 72 61 62 46 54 50 } //1 _GrabFTP
		$a_81_10 = {52 4d 5f 55 4e 49 51 55 45 5f 50 52 4f 43 45 53 53 } //1 RM_UNIQUE_PROCESS
		$a_81_11 = {5f 74 69 6d 65 50 61 73 73 77 6f 72 64 43 68 61 6e 67 65 64 } //1 _timePasswordChanged
		$a_81_12 = {5f 49 73 50 72 6f 63 65 73 73 45 6c 65 76 61 74 65 64 } //1 _IsProcessElevated
		$a_81_13 = {45 78 70 69 72 61 74 69 6f 6e 59 65 61 72 } //1 ExpirationYear
		$a_81_14 = {45 78 70 69 72 61 74 69 6f 6e 4d 6f 6e 74 68 } //1 ExpirationMonth
		$a_81_15 = {43 61 72 64 4e 75 6d 62 65 72 } //1 CardNumber
		$a_81_16 = {48 6f 6c 64 65 72 } //1 Holder
		$a_81_17 = {43 72 65 64 69 74 43 61 72 64 73 } //1 CreditCards
		$a_81_18 = {47 72 61 62 57 61 6c 6c 65 74 73 } //1 GrabWallets
		$a_81_19 = {47 72 61 62 53 63 72 65 65 6e 73 68 6f 74 } //1 GrabScreenshot
		$a_81_20 = {44 65 74 65 63 74 43 72 65 64 69 74 43 61 72 64 54 79 70 65 } //1 DetectCreditCardType
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1+(#a_81_17  & 1)*1+(#a_81_18  & 1)*1+(#a_81_19  & 1)*1+(#a_81_20  & 1)*1) >=21
 
}