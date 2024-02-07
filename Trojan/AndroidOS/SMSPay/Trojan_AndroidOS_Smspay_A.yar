
rule Trojan_AndroidOS_Smspay_A{
	meta:
		description = "Trojan:AndroidOS/Smspay.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 4c 4f 5f 41 50 50 5f 43 48 41 4e } //01 00  GLO_APP_CHAN
		$a_01_1 = {53 54 41 54 55 53 5f 49 4e 54 5f 50 41 59 4d 45 4e 54 5f 54 45 52 4d 53 5f 41 43 43 45 50 54 45 44 } //01 00  STATUS_INT_PAYMENT_TERMS_ACCEPTED
		$a_01_2 = {62 58 52 79 64 58 4e 7a 4c 6e 5a 6c 62 6d 6c 7a 62 79 35 6a 62 32 30 76 59 58 42 70 4c 32 31 30 63 6e 56 7a 63 79 35 6b 62 77 3d 3d } //01 00  bXRydXNzLnZlbmlzby5jb20vYXBpL210cnVzcy5kbw==
		$a_01_3 = {69 73 53 4d 53 50 61 79 6d 65 6e 74 53 75 63 63 65 73 73 66 75 6c 42 53 4f } //00 00  isSMSPaymentSuccessfulBSO
	condition:
		any of ($a_*)
 
}