
rule TrojanSpy_AndroidOS_RewardSteal_I_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/RewardSteal.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {2f 75 73 65 72 4d 65 73 73 61 67 65 2e 70 68 70 } //1 /userMessage.php
		$a_01_1 = {2f 67 65 74 41 70 70 44 61 74 61 2e 70 68 70 } //1 /getAppData.php
		$a_01_2 = {73 65 6e 64 44 61 74 61 54 6f 53 65 72 76 65 72 } //1 sendDataToServer
		$a_01_3 = {4c 63 6f 6d 2f 69 64 62 69 62 61 6e 6b 6f 75 2f 69 64 62 69 62 61 6e 6b } //5 Lcom/idbibankou/idbibank
		$a_01_4 = {4c 63 6f 6d 2f 6c 6f 61 64 2f 6c 6f 61 6e } //5 Lcom/load/loan
		$a_01_5 = {72 65 61 64 4f 6c 64 53 6d 73 4d 65 73 73 61 67 65 73 } //1 readOldSmsMessages
		$a_01_6 = {2f 61 70 70 52 65 67 2e 70 68 70 } //1 /appReg.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}