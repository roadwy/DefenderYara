
rule HackTool_MacOS_AdaptixC2_A_MTB{
	meta:
		description = "HackTool:MacOS/AdaptixC2.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 74 61 73 6b 53 63 72 65 65 6e 73 68 6f 74 } //1 main.taskScreenshot
		$a_01_1 = {6d 61 69 6e 2e 6a 6f 62 44 6f 77 6e 6c 6f 61 64 53 74 61 72 74 } //1 main.jobDownloadStart
		$a_01_2 = {6d 61 69 6e 2e 74 61 73 6b 4a 6f 62 4b 69 6c 6c } //1 main.taskJobKill
		$a_01_3 = {6d 61 69 6e 2e 74 61 73 6b 55 70 6c 6f 61 64 } //1 main.taskUpload
		$a_01_4 = {6d 61 69 6e 2e 74 61 73 6b 53 68 65 6c 6c } //1 main.taskShell
		$a_01_5 = {6d 61 69 6e 2e 6a 6f 62 52 75 6e } //1 main.jobRun
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}