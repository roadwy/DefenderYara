
rule Trojan_AndroidOS_RewardSteal_H_MTB{
	meta:
		description = "Trojan:AndroidOS/RewardSteal.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 65 6c 6c 6f 2f 75 77 65 72 2f 68 65 6c 6c 6f 2f 68 65 6c 6c 6f 2f 67 6f 6f 67 6c 65 2f 69 73 2f 74 68 65 2f 62 65 73 74 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //01 00  hello/uwer/hello/hello/google/is/the/best/MainActivity
		$a_01_1 = {67 65 74 4d 65 73 73 61 67 65 42 6f 64 79 } //01 00  getMessageBody
		$a_01_2 = {53 61 76 65 4d 65 73 73 61 67 65 53 65 72 76 69 63 65 } //01 00  SaveMessageService
		$a_01_3 = {67 65 74 4f 72 69 67 69 6e 61 74 69 6e 67 41 64 64 72 65 73 73 } //00 00  getOriginatingAddress
	condition:
		any of ($a_*)
 
}