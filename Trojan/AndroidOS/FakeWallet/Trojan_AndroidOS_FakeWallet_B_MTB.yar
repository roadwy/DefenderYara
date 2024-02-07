
rule Trojan_AndroidOS_FakeWallet_B_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeWallet.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 74 6f 6b 65 6e 62 61 6e 6b 2f 61 63 74 69 76 69 74 79 2f 73 70 6c 61 73 68 } //01 00  com/tokenbank/activity/splash
		$a_01_1 = {75 70 6c 6f 61 64 70 77 64 5f 72 75 6e } //01 00  uploadpwd_run
		$a_01_2 = {75 70 6c 6f 61 64 4d 6e 65 6d 6f 6e 69 63 } //01 00  uploadMnemonic
		$a_01_3 = {75 70 6c 6f 61 64 55 6e 61 6d 65 5f 50 77 64 } //01 00  uploadUname_Pwd
		$a_01_4 = {75 70 6c 6f 61 64 4d 73 67 } //00 00  uploadMsg
	condition:
		any of ($a_*)
 
}