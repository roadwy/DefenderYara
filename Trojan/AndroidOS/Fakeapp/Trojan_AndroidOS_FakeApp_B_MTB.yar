
rule Trojan_AndroidOS_FakeApp_B_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeApp.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 73 68 69 71 69 2f 71 63 63 65 78 2f 6c 6f 67 69 6e 2f 46 6c 61 73 68 41 63 74 69 76 69 74 79 } //01 00  com/shiqi/qccex/login/FlashActivity
		$a_00_1 = {47 65 74 43 75 73 74 6f 6d 65 72 53 65 72 76 69 63 65 4c 69 6e 6b 52 65 71 75 65 73 74 } //01 00  GetCustomerServiceLinkRequest
		$a_00_2 = {72 65 66 72 65 73 68 41 63 63 65 73 73 54 6f 6b 65 6e } //01 00  refreshAccessToken
		$a_00_3 = {73 61 76 65 54 6f 6b 65 6e 49 6e 66 6f } //01 00  saveTokenInfo
		$a_00_4 = {68 69 64 65 46 61 6b 65 53 74 61 74 75 73 42 61 72 } //01 00  hideFakeStatusBar
		$a_00_5 = {73 61 76 65 53 68 6f 77 42 75 79 43 6f 69 6e 54 69 70 73 } //00 00  saveShowBuyCoinTips
	condition:
		any of ($a_*)
 
}