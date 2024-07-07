
rule TrojanDownloader_BAT_Redline_CL_MTB{
	meta:
		description = "TrojanDownloader:BAT/Redline.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {69 6d 70 6f 72 74 2e 64 61 6c 76 69 6b 2e 61 6e 6e 6f 74 61 74 69 6f 6e 2e 6f 70 74 69 6d 69 7a 61 74 69 6f 6e 2e 6d 6f 64 75 6c 65 36 } //5 import.dalvik.annotation.optimization.module6
		$a_01_1 = {48 61 73 68 43 6f 6c 6c 69 73 69 6f 6e 54 68 72 65 73 68 6f 6c 64 54 59 50 45 44 45 53 43 } //1 HashCollisionThresholdTYPEDESC
		$a_01_2 = {4b 6f 72 65 61 6e 43 61 6c 65 6e 64 61 72 48 61 73 52 65 6c 61 74 65 64 41 63 74 69 76 69 74 79 49 44 } //1 KoreanCalendarHasRelatedActivityID
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 } //1 GetResponse
		$a_01_4 = {6f 70 5f 45 71 75 61 6c 69 74 79 } //1 op_Equality
		$a_01_5 = {53 65 74 75 70 20 66 6f 72 20 57 69 6e 64 6f 77 73 } //1 Setup for Windows
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}