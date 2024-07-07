
rule MonitoringTool_AndroidOS_ZealSpy_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/ZealSpy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0f 00 0f 00 08 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 7a 65 61 6c 2e 7a 65 61 6c 73 70 79 64 65 73 69 67 6e } //10 com.zeal.zealspydesign
		$a_01_1 = {48 69 73 74 6f 72 79 2e 63 73 76 } //1 History.csv
		$a_00_2 = {5f 68 69 64 65 61 70 70 } //1 _hideapp
		$a_00_3 = {73 6d 73 20 64 61 74 61 20 63 61 6c 6c } //1 sms data call
		$a_00_4 = {2f 2e 5a 65 61 6c 52 65 63 6f 72 64 65 72 } //1 /.ZealRecorder
		$a_00_5 = {5f 69 6e 73 74 61 6c 6c 61 70 70 6c 6f 67 73 } //1 _installapplogs
		$a_00_6 = {73 70 79 65 6d 61 69 6c } //1 spyemail
		$a_00_7 = {69 6e 66 6f 73 63 72 65 65 6e } //1 infoscreen
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=15
 
}