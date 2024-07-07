
rule TrojanSpy_AndroidOS_DoNot_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/DoNot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 68 65 6c 6c 6f 2f 75 70 6c 6f 61 64 } //1 /hello/upload
		$a_01_1 = {63 6f 6d 2f 73 79 73 74 65 6d 2f 61 6e 64 72 6f 69 64 2f 75 70 64 61 74 65 72 2f 74 65 6e } //1 com/system/android/updater/ten
		$a_01_2 = {61 6c 72 61 64 64 6f 72 6e } //1 alraddorn
		$a_01_3 = {57 61 70 70 46 69 6c 65 53 65 6e 64 } //1 WappFileSend
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanSpy_AndroidOS_DoNot_A_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/DoNot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {67 65 74 53 6d 73 5f 64 74 } //1 getSms_dt
		$a_00_1 = {4b 65 79 6c 6f 67 73 } //1 Keylogs
		$a_00_2 = {73 72 5f 74 6d 5f 64 75 72 } //1 sr_tm_dur
		$a_00_3 = {6c 69 76 65 5f 72 65 63 31 5f 64 74 74 6d } //1 live_rec1_dttm
		$a_00_4 = {77 74 73 70 5f 72 65 63 } //1 wtsp_rec
		$a_00_5 = {77 61 5f 64 61 74 65 5f 69 64 } //1 wa_date_id
		$a_00_6 = {4b 59 4c 4b 30 30 2e 74 78 74 } //1 KYLK00.txt
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}