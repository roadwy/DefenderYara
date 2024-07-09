
rule Ransom_AndroidOS_Simplocker_A_MTB{
	meta:
		description = "Ransom:AndroidOS/Simplocker.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {4c 63 6f 6d 2f 61 64 75 6c 74 2f 66 72 65 65 2f 68 64 2f [0-20] 76 69 64 65 6f 2f 70 6c 61 79 65 72 } //1
		$a_01_1 = {76 69 64 65 6f 2f 70 6c 61 79 65 72 2f 44 65 76 69 63 65 41 64 6d 69 6e 43 68 65 63 6b 65 72 } //1 video/player/DeviceAdminChecker
		$a_01_2 = {44 65 63 72 79 70 74 53 65 72 76 69 63 65 } //1 DecryptService
		$a_01_3 = {57 61 6b 65 4c 6f 63 6b } //1 WakeLock
		$a_01_4 = {52 75 6e 6e 69 6e 67 54 61 73 6b 49 6e 66 6f } //1 RunningTaskInfo
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}