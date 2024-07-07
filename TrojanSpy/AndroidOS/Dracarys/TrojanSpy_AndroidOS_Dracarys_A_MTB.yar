
rule TrojanSpy_AndroidOS_Dracarys_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Dracarys.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 61 6b 65 42 61 63 6b 50 69 63 74 75 72 65 } //1 takeBackPicture
		$a_01_1 = {63 61 6d 65 72 61 45 78 65 63 53 65 72 76 69 63 65 } //1 cameraExecService
		$a_01_2 = {50 68 6f 6e 65 4d 65 73 73 61 67 65 52 65 70 6f 72 74 57 6f 72 6b 65 72 } //1 PhoneMessageReportWorker
		$a_01_3 = {43 6f 6e 74 61 63 74 49 6e 66 6f 47 61 74 68 65 72 65 72 } //1 ContactInfoGatherer
		$a_01_4 = {64 72 61 63 61 72 79 73 } //1 dracarys
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}