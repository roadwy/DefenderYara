
rule TrojanSpy_AndroidOS_GravityRat_B{
	meta:
		description = "TrojanSpy:AndroidOS/GravityRat.B,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 0d 00 00 "
		
	strings :
		$a_00_0 = {47 65 74 41 63 74 69 76 65 50 72 69 76 61 74 65 44 6f 6d 61 69 6e } //2 GetActivePrivateDomain
		$a_00_1 = {63 61 6c 6c 5f 66 69 6c 65 5f 73 74 61 74 75 73 } //2 call_file_status
		$a_00_2 = {44 61 6d 6e 20 72 65 73 74 61 72 74 69 6e 67 31 32 21 21 20 3a 44 } //2 Damn restarting12!! :D
		$a_00_3 = {73 6d 73 5f 66 69 6c 65 5f 73 74 61 74 75 73 } //2 sms_file_status
		$a_00_4 = {67 65 74 5f 43 44 5f 43 61 6c 6c 73 4c 6f 67 73 } //2 get_CD_CallsLogs
		$a_00_5 = {2f 6a 75 72 61 73 73 69 63 2f 36 63 36 37 64 34 32 38 2e 70 68 70 } //2 /jurassic/6c67d428.php
		$a_00_6 = {2f 68 6f 74 72 69 63 75 6c 74 75 72 65 2f 36 37 31 65 30 30 65 62 2e 70 68 70 } //2 /hotriculture/671e00eb.php
		$a_00_7 = {2f 6f 62 62 2e 6c 6f 67 } //1 /obb.log
		$a_00_8 = {2f 6f 77 77 2e 6c 6f 67 } //1 /oww.log
		$a_00_9 = {63 64 5f 63 6c 5f 6c 6f 67 } //1 cd_cl_log
		$a_00_10 = {63 64 5f 73 6d 5f 6c 6f 67 } //1 cd_sm_log
		$a_00_11 = {2f 63 64 6d 73 2e 6c 6f 67 } //1 /cdms.log
		$a_00_12 = {2f 6c 6f 63 61 74 69 6f 6e 2e 6c 6f 67 } //1 /location.log
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1) >=8
 
}