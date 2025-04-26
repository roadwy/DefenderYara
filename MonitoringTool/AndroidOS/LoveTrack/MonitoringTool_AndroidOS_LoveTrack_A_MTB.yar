
rule MonitoringTool_AndroidOS_LoveTrack_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/LoveTrack.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 62 65 74 74 65 72 74 6f 6d 6f 72 72 6f 77 61 70 70 73 2f 73 70 79 79 6f 75 72 6c 6f 76 65 } //2 com/bettertomorrowapps/spyyourlove
		$a_00_1 = {73 6d 73 5f 75 6e 6c 6f 63 6b 5f 66 75 6c 6c } //1 sms_unlock_full
		$a_00_2 = {63 6f 6e 74 65 6e 74 3a 2f 2f 63 61 6c 6c 5f 6c 6f 67 2f 63 61 6c 6c 73 } //1 content://call_log/calls
		$a_00_3 = {70 61 72 74 6e 65 72 5f 6c 61 73 74 5f 73 79 6e 63 } //1 partner_last_sync
		$a_00_4 = {6a 6f 75 72 6e 61 6c 2e 74 6d 70 } //1 journal.tmp
		$a_00_5 = {59 6f 75 20 63 61 6e 27 74 20 75 73 65 20 43 6f 75 70 6c 65 20 54 72 61 63 6b 65 72 20 77 69 74 68 6f 75 74 20 70 72 6f 70 65 72 20 63 6f 6e 73 65 6e 74 } //1 You can't use Couple Tracker without proper consent
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}