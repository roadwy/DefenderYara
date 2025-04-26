
rule TrojanSpy_AndroidOS_CarbonSteal_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/CarbonSteal.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {52 6f 62 4d 6f 6e 65 79 53 65 72 76 69 63 65 } //1 RobMoneyService
		$a_00_1 = {43 61 6c 6c 6c 6f 67 67 65 72 } //1 Calllogger
		$a_00_2 = {2f 66 69 6c 65 73 4d 61 6e 61 67 65 72 2f 75 70 6c 6f 61 64 46 69 6c 65 } //1 /filesManager/uploadFile
		$a_00_3 = {2f 74 72 69 67 67 65 72 49 6e 66 6f 4d 61 6e 61 67 65 72 2f 61 64 64 54 72 69 67 67 65 72 49 6e 66 6f } //1 /triggerInfoManager/addTriggerInfo
		$a_00_4 = {73 63 72 65 65 6e 63 61 70 20 2d 70 } //1 screencap -p
		$a_00_5 = {36 30 30 36 2e 75 70 75 70 64 61 74 65 2e 63 6e } //1 6006.upupdate.cn
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}