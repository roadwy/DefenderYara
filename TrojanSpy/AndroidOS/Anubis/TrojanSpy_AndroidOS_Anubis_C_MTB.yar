
rule TrojanSpy_AndroidOS_Anubis_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Anubis.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {4c 79 65 64 2f 66 62 64 62 6b 2f 76 7a 65 2f 69 66 64 66 24 69 66 64 66 } //1 Lyed/fbdbk/vze/ifdf$ifdf
		$a_00_1 = {6b 69 6c 6c 42 61 63 6b 67 72 6f 75 6e 64 50 72 6f 63 65 73 73 65 73 } //1 killBackgroundProcesses
		$a_00_2 = {63 72 65 61 74 65 53 63 72 65 65 6e 43 61 70 74 75 72 65 49 6e 74 65 6e 74 } //1 createScreenCaptureIntent
		$a_00_3 = {53 45 4e 44 5f 53 4d 53 } //1 SEND_SMS
		$a_02_4 = {2f 6f 31 6f 2f 61 90 02 03 2e 70 68 70 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=4
 
}