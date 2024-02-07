
rule Trojan_AndroidOS_Ramha_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Ramha.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 6f 6f 6c 73 2f 61 70 70 2f 64 6f 77 6e 6c 6f 61 64 65 72 73 } //01 00  tools/app/downloaders
		$a_01_1 = {56 65 72 69 66 79 48 61 6d 72 61 68 41 76 61 6c 4f 74 70 41 63 74 69 76 69 74 79 } //01 00  VerifyHamrahAvalOtpActivity
		$a_01_2 = {2f 66 61 6e 61 70 2e 72 74 65 6c 6c 73 65 72 76 65 72 73 2e 63 6f 6d 2f 61 70 69 2f 76 65 72 69 66 79 5f 6f 74 70 5f 72 65 71 75 65 73 74 5f 6b 65 79 62 6f 61 72 64 2f } //01 00  /fanap.rtellservers.com/api/verify_otp_request_keyboard/
		$a_01_3 = {54 6f 6f 6c 73 53 6d 73 52 65 63 65 69 76 65 72 } //00 00  ToolsSmsReceiver
	condition:
		any of ($a_*)
 
}