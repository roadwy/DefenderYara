
rule HackTool_BAT_FrostyStash_A_dha{
	meta:
		description = "HackTool:BAT/FrostyStash.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0f 00 00 "
		
	strings :
		$a_01_0 = {55 00 34 00 4f 00 67 00 46 00 73 00 32 00 6f 00 70 00 78 00 6e 00 48 00 4b 00 55 00 55 00 77 00 66 00 32 00 38 00 30 00 44 00 76 00 55 00 47 00 78 00 65 00 77 00 67 00 71 00 6c 00 42 00 4a 00 4b 00 7a 00 48 00 5a 00 70 00 57 00 68 00 67 00 38 00 4e 00 50 00 72 00 32 00 41 00 66 00 30 00 44 00 39 00 } //10 U4OgFs2opxnHKUUwf280DvUGxewgqlBJKzHZpWhg8NPr2Af0D9
		$a_01_1 = {73 00 79 00 73 00 74 00 65 00 6d 00 5f 00 64 00 61 00 74 00 61 00 5f 00 73 00 69 00 7a 00 65 00 } //1 system_data_size
		$a_01_2 = {74 00 69 00 6d 00 65 00 5f 00 73 00 63 00 61 00 6c 00 65 00 } //1 time_scale
		$a_01_3 = {69 00 6e 00 74 00 65 00 72 00 76 00 61 00 6c 00 5f 00 65 00 6e 00 67 00 69 00 6e 00 65 00 } //1 interval_engine
		$a_01_4 = {69 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 5f 00 69 00 64 00 } //1 internal_id
		$a_01_5 = {69 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 5f 00 6b 00 65 00 79 00 } //1 internal_key
		$a_01_6 = {72 00 61 00 74 00 65 00 5f 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 } //1 rate_control
		$a_01_7 = {73 00 70 00 61 00 6e 00 5f 00 6d 00 69 00 6e 00 } //1 span_min
		$a_01_8 = {73 00 70 00 61 00 6e 00 5f 00 6d 00 61 00 78 00 } //1 span_max
		$a_01_9 = {64 00 61 00 79 00 73 00 5f 00 6e 00 6f 00 74 00 5f 00 77 00 6f 00 72 00 6b 00 } //1 days_not_work
		$a_01_10 = {54 4d 52 5f 45 6e 67 69 6e 65 } //1 TMR_Engine
		$a_01_11 = {54 4d 52 5f 43 68 65 63 6b 45 76 65 6e 74 } //1 TMR_CheckEvent
		$a_01_12 = {54 4d 52 5f 4b 65 65 70 41 6c 69 76 65 } //1 TMR_KeepAlive
		$a_01_13 = {54 4d 52 5f 47 65 6e 4b 65 79 73 } //1 TMR_GenKeys
		$a_01_14 = {54 4d 52 5f 43 68 65 63 6b 44 42 } //1 TMR_CheckDB
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=10
 
}