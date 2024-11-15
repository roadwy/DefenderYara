
rule Backdoor_AndroidOS_Vultur_C_MTB{
	meta:
		description = "Backdoor:AndroidOS/Vultur.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {76 6e 63 5f 65 6e 61 62 6c 65 64 } //1 vnc_enabled
		$a_01_1 = {4e 67 72 6f 6b 44 6f 77 6e 6c 6f 61 64 57 6f 72 6b 65 72 } //1 NgrokDownloadWorker
		$a_01_2 = {56 6e 63 53 65 73 73 69 6f 6e 43 6f 6e 66 69 67 } //1 VncSessionConfig
		$a_01_3 = {73 65 74 43 6c 69 70 54 6f 53 63 72 65 65 6e 45 6e 61 62 6c 65 64 } //1 setClipToScreenEnabled
		$a_01_4 = {4d 65 64 69 61 55 70 6c 6f 61 64 57 6f 72 6b 65 72 } //1 MediaUploadWorker
		$a_01_5 = {53 63 72 65 65 6e 52 65 63 6f 72 64 57 6f 72 6b 65 72 } //1 ScreenRecordWorker
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}