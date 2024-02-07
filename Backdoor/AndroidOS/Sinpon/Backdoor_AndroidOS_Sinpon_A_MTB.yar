
rule Backdoor_AndroidOS_Sinpon_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Sinpon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 61 63 6b 43 6f 6e 6e 54 61 73 6b } //01 00  BackConnTask
		$a_01_1 = {72 65 73 75 6c 74 5f 49 6e 73 74 61 6c 6c 65 64 41 70 70 } //01 00  result_InstalledApp
		$a_01_2 = {67 65 74 6b 65 72 6e 65 6c 41 70 70 } //01 00  getkernelApp
		$a_01_3 = {53 65 6e 64 53 6d 73 4d 65 73 } //01 00  SendSmsMes
		$a_01_4 = {6b 69 6c 6c 46 69 6c 65 } //01 00  killFile
		$a_01_5 = {50 68 6f 6e 65 53 79 6e 63 53 65 72 76 69 63 65 } //01 00  PhoneSyncService
		$a_01_6 = {55 70 6c 6f 61 64 54 61 73 6b } //00 00  UploadTask
	condition:
		any of ($a_*)
 
}