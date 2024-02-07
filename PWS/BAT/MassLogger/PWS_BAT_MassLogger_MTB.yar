
rule PWS_BAT_MassLogger_MTB{
	meta:
		description = "PWS:BAT/MassLogger!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 15 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 65 74 43 72 65 64 65 6e 74 69 61 6c 73 } //01 00  GetCredentials
		$a_01_1 = {5f 66 6f 72 6d 53 75 62 6d 69 74 55 52 4c } //01 00  _formSubmitURL
		$a_01_2 = {5f 41 64 61 70 74 65 72 52 41 4d } //01 00  _AdapterRAM
		$a_01_3 = {5f 47 72 61 62 56 50 4e } //01 00  _GrabVPN
		$a_01_4 = {5f 4e 6f 72 64 56 50 4e } //01 00  _NordVPN
		$a_01_5 = {5f 4f 70 65 6e 56 50 4e } //01 00  _OpenVPN
		$a_01_6 = {5f 50 72 6f 74 6f 6e 56 50 4e } //01 00  _ProtonVPN
		$a_01_7 = {52 4d 5f 50 52 4f 43 45 53 53 5f 49 4e 46 4f } //01 00  RM_PROCESS_INFO
		$a_01_8 = {5f 42 6c 61 63 6b 6c 69 73 74 65 64 49 50 } //01 00  _BlacklistedIP
		$a_01_9 = {5f 47 72 61 62 46 54 50 } //01 00  _GrabFTP
		$a_01_10 = {52 4d 5f 55 4e 49 51 55 45 5f 50 52 4f 43 45 53 53 } //01 00  RM_UNIQUE_PROCESS
		$a_01_11 = {5f 74 69 6d 65 50 61 73 73 77 6f 72 64 43 68 61 6e 67 65 64 } //01 00  _timePasswordChanged
		$a_01_12 = {5f 49 73 50 72 6f 63 65 73 73 45 6c 65 76 61 74 65 64 } //01 00  _IsProcessElevated
		$a_01_13 = {45 78 70 69 72 61 74 69 6f 6e 59 65 61 72 } //01 00  ExpirationYear
		$a_01_14 = {45 78 70 69 72 61 74 69 6f 6e 4d 6f 6e 74 68 } //01 00  ExpirationMonth
		$a_01_15 = {43 61 72 64 4e 75 6d 62 65 72 } //01 00  CardNumber
		$a_01_16 = {48 6f 6c 64 65 72 } //01 00  Holder
		$a_01_17 = {43 72 65 64 69 74 43 61 72 64 73 } //01 00  CreditCards
		$a_01_18 = {47 72 61 62 57 61 6c 6c 65 74 73 } //01 00  GrabWallets
		$a_01_19 = {47 72 61 62 53 63 72 65 65 6e 73 68 6f 74 } //01 00  GrabScreenshot
		$a_01_20 = {44 65 74 65 63 74 43 72 65 64 69 74 43 61 72 64 54 79 70 65 } //00 00  DetectCreditCardType
	condition:
		any of ($a_*)
 
}