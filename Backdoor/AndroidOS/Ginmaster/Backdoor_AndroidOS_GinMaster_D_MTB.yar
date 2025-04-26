
rule Backdoor_AndroidOS_GinMaster_D_MTB{
	meta:
		description = "Backdoor:AndroidOS/GinMaster.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 77 6f 77 65 69 71 75 2f 6a 72 78 2f 63 6f 6e 74 72 6f 6c 6c 65 72 } //1 Lcom/woweiqu/jrx/controller
		$a_01_1 = {4c 63 6f 6d 2f 73 6f 73 74 61 74 69 6f 6e 2f 6c 69 62 72 61 72 79 2f 73 64 6b } //1 Lcom/sostation/library/sdk
		$a_01_2 = {63 6c 6f 73 65 57 65 62 56 69 65 77 53 70 6c 61 73 68 } //1 closeWebViewSplash
		$a_01_3 = {63 72 65 61 74 65 41 75 64 69 6f 44 69 72 57 69 74 68 41 70 70 50 61 63 6b 61 67 65 4e 61 6d 65 } //1 createAudioDirWithAppPackageName
		$a_01_4 = {67 65 74 4c 61 73 74 4b 6e 6f 77 6e 4c 6f 63 61 74 69 6f 6e } //1 getLastKnownLocation
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}