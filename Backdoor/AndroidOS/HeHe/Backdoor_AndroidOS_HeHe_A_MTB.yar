
rule Backdoor_AndroidOS_HeHe_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/HeHe.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {49 6e 63 6f 6d 65 43 61 6c 6c 41 6e 64 53 6d 73 52 65 63 65 69 76 65 72 } //1 IncomeCallAndSmsReceiver
		$a_00_1 = {64 65 6c 65 74 65 20 73 6d 73 20 63 61 6c 6c } //1 delete sms call
		$a_00_2 = {74 72 61 6e 73 66 65 72 43 61 6c 6c 49 6e 66 6f } //1 transferCallInfo
		$a_00_3 = {6d 73 67 2e 61 70 6b } //1 msg.apk
		$a_00_4 = {53 69 6c 65 6e 63 65 49 6e 73 74 61 6c 6c } //1 SilenceInstall
		$a_00_5 = {69 6e 74 65 72 63 65 70 74 49 6e 66 6f } //1 interceptInfo
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}