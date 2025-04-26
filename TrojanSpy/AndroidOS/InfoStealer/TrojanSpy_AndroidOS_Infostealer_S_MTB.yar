
rule TrojanSpy_AndroidOS_Infostealer_S_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Infostealer.S!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 43 6f 6e 74 61 63 74 4c 69 73 74 } //1 getContactList
		$a_03_1 = {2f 70 61 79 [0-05] 2e 70 68 70 3f 6e 61 6d 65 3d } //1
		$a_01_2 = {2f 6d 65 73 73 61 67 65 62 6f 74 2e 70 68 70 } //1 /messagebot.php
		$a_01_3 = {63 6f 6d 2d 7a 65 72 6f 6f 6e 65 2d 64 69 76 61 72 61 6f 70 2d 53 6d 73 52 65 63 65 69 76 65 72 } //1 com-zeroone-divaraop-SmsReceiver
		$a_01_4 = {67 65 74 4d 65 73 73 61 67 65 42 6f 64 79 } //1 getMessageBody
		$a_01_5 = {68 61 73 5f 70 68 6f 6e 65 5f 6e 75 6d 62 65 72 } //1 has_phone_number
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}