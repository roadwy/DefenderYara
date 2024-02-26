
rule Trojan_AndroidOS_Rewardsteal_D{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.D,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 20 46 69 65 6c 64 20 72 65 71 75 69 72 65 73 20 31 36 20 64 69 67 69 74 } //02 00  This Field requires 16 digit
		$a_01_1 = {50 65 72 6d 69 73 69 69 6f 6e 65 52 65 71 75 65 73 74 } //00 00  PermisiioneRequest
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_Rewardsteal_D_2{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.D,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 69 63 69 63 69 2f 6f 74 70 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 24 62 69 6e 64 57 65 62 24 32 } //01 00  com/icici/otp/MainActivity$bindWeb$2
		$a_01_1 = {6c 65 74 2d 46 6f 72 6d 41 63 74 69 76 69 74 79 24 66 65 74 63 68 53 4d 53 4d 65 73 73 61 67 65 73 24 31 } //00 00  let-FormActivity$fetchSMSMessages$1
	condition:
		any of ($a_*)
 
}