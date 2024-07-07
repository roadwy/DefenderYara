
rule MonitoringTool_AndroidOS_Toreoc_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Toreoc.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_00_0 = {68 69 64 65 6e 6f 74 69 66 69 63 61 74 69 6f 6e } //1 hidenotification
		$a_00_1 = {70 68 6f 6e 65 5f 70 69 63 6b 65 72 5f 61 70 70 6c 79 5f 66 6f 72 5f 6f 75 74 67 6f 69 6e 67 } //1 phone_picker_apply_for_outgoing
		$a_00_2 = {43 41 4c 4c 5f 4c 4f 47 } //1 CALL_LOG
		$a_00_3 = {61 6c 6c 6f 77 52 65 63 6f 72 64 56 69 61 53 6d 73 } //1 allowRecordViaSms
		$a_00_4 = {68 69 64 65 52 65 63 6f 72 64 69 6e 67 53 74 72 61 74 65 67 79 } //1 hideRecordingStrategy
		$a_00_5 = {72 65 63 6f 72 64 41 66 74 65 72 43 61 6c 6c 53 74 61 72 74 } //1 recordAfterCallStart
		$a_00_6 = {53 32 43 61 6c 6c 52 65 63 5f 64 6f 6e 74 5f 73 68 6f 77 } //1 S2CallRec_dont_show
		$a_00_7 = {74 74 70 73 3a 2f 2f 77 77 77 2e 6b 69 6c 6c 65 72 6d 6f 62 69 6c 65 73 6f 66 74 77 61 72 65 2e 63 6f 6d 2f 66 6f 72 2f 64 65 76 69 63 65 73 2f } //1 ttps://www.killermobilesoftware.com/for/devices/
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=6
 
}