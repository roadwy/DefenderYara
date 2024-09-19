
rule Trojan_AndroidOS_Rewardsteal_C{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.C,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 61 6e 61 72 72 61 35 34 35 2d 64 65 66 61 75 6c 74 2d 72 74 64 62 2e 66 69 72 65 62 61 73 65 69 6f 2e 63 6f 6d 2f } //1 canarra545-default-rtdb.firebaseio.com/
		$a_01_1 = {50 6c 65 61 73 65 20 57 61 69 74 20 32 34 68 } //1 Please Wait 24h
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_AndroidOS_Rewardsteal_C_2{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.C,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 45 4e 44 5f 53 4d 53 5f 50 45 52 4d 49 53 53 49 4f 4e 5f 52 45 51 55 45 53 54 5f 43 4f 44 45 } //2 SEND_SMS_PERMISSION_REQUEST_CODE
		$a_01_1 = {43 61 72 64 20 43 56 56 20 69 73 20 52 65 71 75 69 72 65 64 20 21 } //2 Card CVV is Required !
		$a_01_2 = {2f 72 6f 6f 74 2f 61 70 69 2f 75 73 65 72 2f 73 6d 73 } //2 /root/api/user/sms
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}