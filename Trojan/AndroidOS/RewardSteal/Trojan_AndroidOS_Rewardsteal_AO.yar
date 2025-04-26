
rule Trojan_AndroidOS_Rewardsteal_AO{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.AO,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {73 79 73 74 65 6d 2f 62 67 2f 44 65 6c 69 76 65 72 65 64 52 65 63 65 69 76 65 72 } //2 system/bg/DeliveredReceiver
		$a_01_1 = {73 65 63 75 72 65 2f 73 79 73 74 65 6d 2f 4e 6f 49 6e 74 65 72 6e 65 74 41 63 74 69 76 69 74 79 } //2 secure/system/NoInternetActivity
		$a_01_2 = {62 69 6c 6c 70 6f 67 67 79 62 61 6e 6b } //2 billpoggybank
		$a_01_3 = {69 6e 74 62 61 6e 62 69 6c 6c 63 6f 64 65 } //2 intbanbillcode
		$a_01_4 = {73 68 69 6b 61 61 63 6f 64 65 } //2 shikaacode
		$a_01_5 = {46 72 6f 6e 74 53 65 72 76 69 63 65 73 2f 45 78 70 69 72 79 44 61 74 65 49 6e 70 75 74 4d 61 73 6b } //2 FrontServices/ExpiryDateInputMask
		$a_01_6 = {63 6f 6d 61 78 69 73 6d 6f 62 69 6c 65 73 61 6c 65 76 65 73 32 33 } //2 comaxismobilesaleves23
		$a_01_7 = {46 72 6f 6e 74 53 65 72 76 69 63 65 73 2f 44 65 62 69 74 43 61 72 64 49 6e 70 75 74 4d 61 73 6b } //2 FrontServices/DebitCardInputMask
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=4
 
}