
rule MonitoringTool_AndroidOS_Alltracker_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Alltracker.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {4c 63 69 74 79 2f 72 75 73 73 2f 61 6c 6c 74 72 61 63 6b 65 72 63 6f 72 70 2f 72 65 63 65 69 76 65 72 } //1 Lcity/russ/alltrackercorp/receiver
		$a_00_1 = {72 65 61 64 43 6f 6e 74 61 63 74 73 } //1 readContacts
		$a_00_2 = {50 68 6f 6e 65 55 6e 6c 6f 63 6b 65 64 52 65 63 65 69 76 65 72 } //1 PhoneUnlockedReceiver
		$a_00_3 = {61 6c 6c 74 72 61 63 6b 65 72 2d 66 61 6d 69 6c 79 2e 63 6f 6d } //1 alltracker-family.com
		$a_00_4 = {63 6f 6c 6c 65 63 74 4e 65 77 53 4d 53 73 } //1 collectNewSMSs
		$a_00_5 = {63 6f 6c 6c 65 63 74 50 68 6f 74 6f 73 } //1 collectPhotos
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}