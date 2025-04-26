
rule MonitoringTool_AndroidOS_Anlost_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Anlost.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {67 65 74 74 69 6e 67 20 53 6d 73 20 64 65 74 61 69 6c 73 } //1 getting Sms details
		$a_00_1 = {53 4d 53 5f 52 45 41 44 5f 43 4f 4c 55 4d 4e } //1 SMS_READ_COLUMN
		$a_00_2 = {6c 6f 73 74 61 70 70 } //1 lostapp
		$a_00_3 = {57 69 70 65 20 70 68 6f 6e 65 } //1 Wipe phone
		$a_00_4 = {53 4d 53 20 47 50 53 20 69 6e 69 74 69 61 74 65 64 } //1 SMS GPS initiated
		$a_00_5 = {61 6e 64 72 6f 69 64 6c 6f 73 74 20 77 69 70 65 } //1 androidlost wipe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}