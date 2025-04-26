
rule MonitoringTool_AndroidOS_Guardian_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Guardian.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 6c 65 6e 6f 76 6f 2e 73 61 66 65 63 65 6e 74 65 72 } //1 com.lenovo.safecenter
		$a_00_1 = {77 65 69 62 6f 2e 63 6f 6d 2f 6c 65 61 6e 71 75 61 6e } //1 weibo.com/leanquan
		$a_00_2 = {71 76 5f 62 61 73 65 2e 61 6d 66 } //1 qv_base.amf
		$a_00_3 = {55 70 4c 6f 61 64 53 4d 53 } //1 UpLoadSMS
		$a_00_4 = {6b 69 6c 6c 70 72 6f 63 65 73 73 } //1 killprocess
		$a_00_5 = {4c 41 53 54 5f 53 41 56 45 5f 53 45 4e 54 5f 53 4d 53 5f 49 44 } //1 LAST_SAVE_SENT_SMS_ID
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}