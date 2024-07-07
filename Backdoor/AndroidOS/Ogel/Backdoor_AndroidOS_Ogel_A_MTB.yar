
rule Backdoor_AndroidOS_Ogel_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Ogel.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {49 4d 53 49 5f 4e 41 4b 45 44 } //1 IMSI_NAKED
		$a_00_1 = {50 68 6f 6e 65 43 72 61 73 68 41 63 74 69 76 69 74 79 } //1 PhoneCrashActivity
		$a_00_2 = {77 72 69 74 65 61 70 6b 5f 66 6f 72 73 64 63 61 72 64 } //1 writeapk_forsdcard
		$a_01_3 = {42 45 47 49 4e 20 53 4d 53 20 41 64 61 70 74 65 72 } //1 BEGIN SMS Adapter
		$a_00_4 = {73 65 6e 64 53 4d 53 20 73 6c 65 65 70 } //1 sendSMS sleep
		$a_00_5 = {63 61 6e 6e 6f 74 20 66 61 6b 65 } //1 cannot fake
		$a_00_6 = {45 6e 61 62 6c 65 53 6d 73 72 65 70 6c 79 } //1 EnableSmsreply
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}