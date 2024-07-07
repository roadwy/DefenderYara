
rule Trojan_AndroidOS_Rewardsteal_J{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.J,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 6e 64 75 73 63 61 72 64 2f 50 6c 65 61 73 65 57 61 69 74 41 63 74 69 76 69 74 79 } //2 induscard/PleaseWaitActivity
		$a_01_1 = {78 79 7a 2f 61 70 69 2f 6d 65 73 73 65 67 65 2e 70 68 70 } //2 xyz/api/messege.php
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}