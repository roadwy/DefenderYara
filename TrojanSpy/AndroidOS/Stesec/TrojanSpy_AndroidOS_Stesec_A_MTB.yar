
rule TrojanSpy_AndroidOS_Stesec_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Stesec.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 65 63 75 72 69 74 79 53 6d 73 45 78 65 63 53 65 6e 64 } //2 SecuritySmsExecSend
		$a_00_1 = {53 65 63 75 72 69 74 79 53 6d 73 53 65 72 76 69 63 65 } //2 SecuritySmsService
		$a_00_2 = {45 78 65 63 53 65 6e 64 53 6d 73 } //2 ExecSendSms
		$a_00_3 = {2f 64 61 74 61 2f 65 6d 6f 64 65 2f 73 6d 73 6d 6f 64 65 2e 63 6f 6e 66 } //1 /data/emode/smsmode.conf
		$a_00_4 = {61 6e 74 69 66 61 6b 65 73 6d 73 } //1 antifakesms
		$a_00_5 = {67 65 74 5a 74 65 53 6d 73 49 6e 66 6f } //1 getZteSmsInfo
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=7
 
}