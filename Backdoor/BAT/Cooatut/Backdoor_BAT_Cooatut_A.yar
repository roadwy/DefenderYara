
rule Backdoor_BAT_Cooatut_A{
	meta:
		description = "Backdoor:BAT/Cooatut.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0b 00 00 "
		
	strings :
		$a_01_0 = {43 00 6c 00 6f 00 75 00 64 00 20 00 4e 00 65 00 74 00 } //1 Cloud Net
		$a_01_1 = {47 65 74 52 6f 6f 74 44 69 72 } //1 GetRootDir
		$a_01_2 = {4b 65 79 53 74 72 6f 6b 65 4d 6f 6e 69 74 6f 72 } //1 KeyStrokeMonitor
		$a_01_3 = {4d 61 6c 77 61 72 65 52 65 6d 6f 76 65 72 } //1 MalwareRemover
		$a_01_4 = {48 65 75 72 69 73 74 69 63 53 63 61 6e } //1 HeuristicScan
		$a_01_5 = {53 74 61 72 74 53 74 72 65 73 73 6f 72 } //1 StartStressor
		$a_01_6 = {55 70 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 } //1 UploadAndExecute
		$a_01_7 = {42 6c 6f 63 6b 57 65 62 73 69 74 65 } //1 BlockWebsite
		$a_01_8 = {52 75 6e 43 61 6d } //1 RunCam
		$a_01_9 = {52 75 6e 4c 6f 6f 70 } //1 RunLoop
		$a_01_10 = {52 65 6d 6f 74 65 41 75 64 69 6f } //1 RemoteAudio
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=9
 
}