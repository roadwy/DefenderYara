
rule MonitoringTool_AndroidOS_ASpy_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/ASpy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 61 73 2e 73 63 72 65 65 6e 72 65 63 6f 72 64 65 72 } //1 com.as.screenrecorder
		$a_00_1 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 73 63 72 65 65 6e 63 61 70 20 2d 70 } //1 /system/bin/screencap -p
		$a_00_2 = {41 75 74 6f 44 65 6c 65 74 65 } //1 AutoDelete
		$a_00_3 = {52 65 63 6f 72 64 53 63 72 65 65 6e 52 6f 6f 74 } //1 RecordScreenRoot
		$a_00_4 = {48 69 64 65 4e 6f 74 69 66 69 63 61 74 69 6f 6e 43 6c 69 63 6b } //1 HideNotificationClick
		$a_00_5 = {61 63 74 61 63 63 } //1 actacc
		$a_00_6 = {64 65 6c 65 74 65 64 61 6c 6c } //1 deletedall
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}