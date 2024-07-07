
rule Backdoor_AndroidOS_SpyDealer_DS_MTB{
	meta:
		description = "Backdoor:AndroidOS/SpyDealer.DS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {47 65 74 48 69 73 74 6f 72 79 43 61 6c 6c } //1 GetHistoryCall
		$a_00_1 = {2f 73 74 61 74 75 73 2f 64 65 61 6c 2f 62 6f 64 79 2f 64 65 61 6c 61 70 70 2e 61 73 70 } //1 /status/deal/body/dealapp.asp
		$a_00_2 = {53 4d 53 5f 55 52 49 5f 41 4c 4c } //1 SMS_URI_ALL
		$a_00_3 = {67 65 74 49 6e 63 6f 6d 65 4e 75 6d 62 65 72 41 6e 64 54 69 6d 65 } //1 getIncomeNumberAndTime
		$a_00_4 = {6d 5f 61 74 74 61 63 6b 66 69 6c 65 } //1 m_attackfile
		$a_00_5 = {61 75 74 6f 72 65 70 63 61 6c 6c 6e 75 6d } //1 autorepcallnum
		$a_00_6 = {73 74 61 72 74 52 6f 6f 74 } //1 startRoot
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}