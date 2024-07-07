
rule TrojanSpy_AndroidOS_Asacub_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Asacub.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 41 6c 61 72 6d 52 65 63 65 69 76 65 72 53 6d 73 4d 61 6e } //2 /AlarmReceiverSmsMan
		$a_01_1 = {2f 48 65 61 64 6c 65 73 73 53 6d 73 53 65 6e 64 53 65 72 76 69 63 65 } //2 /HeadlessSmsSendService
		$a_01_2 = {2f 41 6c 61 72 6d 52 65 63 65 69 76 65 72 4b 6e 6f 63 6b } //1 /AlarmReceiverKnock
		$a_01_3 = {2f 41 63 74 69 76 69 74 79 43 61 72 64 } //1 /ActivityCard
		$a_01_4 = {2f 53 72 76 50 72 6f 63 4d 6f 6e } //1 /SrvProcMon
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}