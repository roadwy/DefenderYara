
rule Trojan_AndroidOS_HiddenApp_B_MTB{
	meta:
		description = "Trojan:AndroidOS/HiddenApp.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 6c 61 2e 6d 69 2e 6c 61 6d 69 73 65 72 76 69 63 65 } //1 com.la.mi.lamiservice
		$a_00_1 = {5f 70 72 6f 63 65 73 73 64 61 74 61 70 75 73 68 } //1 _processdatapush
		$a_00_2 = {53 68 6f 77 4f 72 48 69 64 65 41 70 70 46 72 6f 6d 4c 75 6e 63 68 65 72 } //1 ShowOrHideAppFromLuncher
		$a_00_3 = {52 65 73 75 6d 61 62 6c 65 53 75 62 5f 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 ResumableSub_DownloadFile
		$a_00_4 = {49 6e 73 74 61 6c 6c 54 61 72 67 65 74 32 33 41 6e 64 41 62 6f 76 65 } //1 InstallTarget23AndAbove
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}