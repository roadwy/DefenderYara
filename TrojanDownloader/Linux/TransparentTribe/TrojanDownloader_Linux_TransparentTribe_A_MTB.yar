
rule TrojanDownloader_Linux_TransparentTribe_A_MTB{
	meta:
		description = "TrojanDownloader:Linux/TransparentTribe.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 28 2a 5f 5f 5f 43 6c 69 65 6e 74 53 74 72 75 63 74 29 2e 5f 5f 5f 49 6e 73 74 61 6c 6c 50 65 72 73 69 73 74 65 6e 63 65 46 65 61 74 75 72 65 73 } //2 main.(*___ClientStruct).___InstallPersistenceFeatures
		$a_01_1 = {6d 61 69 6e 2e 28 2a 5f 5f 5f 43 6c 69 65 6e 74 53 74 72 75 63 74 29 2e 5f 5f 5f 50 72 6f 63 65 73 73 55 70 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 } //2 main.(*___ClientStruct).___ProcessUploadAndExecute
		$a_01_2 = {6d 61 69 6e 2e 28 2a 5f 5f 5f 43 6c 69 65 6e 74 53 74 72 75 63 74 29 2e 5f 5f 5f 4f 62 74 61 69 6e 45 78 74 65 72 6e 61 6c 49 50 } //2 main.(*___ClientStruct).___ObtainExternalIP
		$a_01_3 = {6d 61 69 6e 2e 28 2a 5f 5f 5f 43 6c 69 65 6e 74 53 74 72 75 63 74 29 2e 5f 5f 5f 41 64 64 54 6f 43 72 6f 6e 74 61 62 53 63 68 65 64 75 6c 65 72 } //2 main.(*___ClientStruct).___AddToCrontabScheduler
		$a_01_4 = {6d 61 69 6e 2e 28 2a 5f 5f 5f 43 6c 69 65 6e 74 53 74 72 75 63 74 29 2e 5f 5f 5f 52 75 6e 49 6e 53 74 65 61 6c 74 68 4d 6f 64 65 } //2 main.(*___ClientStruct).___RunInStealthMode
		$a_01_5 = {6d 61 69 6e 2e 28 2a 5f 5f 5f 43 6c 69 65 6e 74 53 74 72 75 63 74 29 2e 5f 5f 5f 41 74 74 65 6d 70 74 4c 6f 63 61 74 69 6f 6e 52 65 74 72 69 65 76 61 6c } //1 main.(*___ClientStruct).___AttemptLocationRetrieval
		$a_01_6 = {6d 61 69 6e 2e 5f 5f 5f 65 76 61 73 69 6f 6e 5f 74 72 61 6e 73 66 6f 72 6d 5f 73 74 72 69 6e 67 } //1 main.___evasion_transform_string
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=10
 
}