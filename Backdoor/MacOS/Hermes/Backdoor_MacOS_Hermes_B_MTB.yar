
rule Backdoor_MacOS_Hermes_B_MTB{
	meta:
		description = "Backdoor:MacOS/Hermes.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 59 54 48 49 43 5f 50 4f 53 54 5f 52 45 53 50 4f 4e 53 45 } //1 MYTHIC_POST_RESPONSE
		$a_01_1 = {64 6f 77 6e 6c 6f 61 64 49 73 53 63 72 65 65 6e 73 68 6f 74 } //1 downloadIsScreenshot
		$a_01_2 = {75 70 6c 6f 61 64 54 6f 74 61 6c 43 68 75 6e 6b 73 } //1 uploadTotalChunks
		$a_01_3 = {48 45 52 4d 45 53 5f 50 4f 53 54 5f 52 45 53 50 4f 4e 53 45 } //1 HERMES_POST_RESPONSE
		$a_01_4 = {73 63 72 65 65 6e 73 68 6f 74 54 6f 74 61 6c 44 69 73 70 6c 61 79 73 } //1 screenshotTotalDisplays
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}