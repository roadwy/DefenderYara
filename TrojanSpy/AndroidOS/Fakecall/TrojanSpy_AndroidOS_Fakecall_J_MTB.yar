
rule TrojanSpy_AndroidOS_Fakecall_J_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakecall.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {73 65 6e 64 50 68 6f 6e 65 49 6e 66 6f 54 6f 53 65 72 76 65 72 } //1 sendPhoneInfoToServer
		$a_00_1 = {72 75 6e 57 68 6f 57 68 6f } //1 runWhoWho
		$a_00_2 = {72 65 71 75 65 73 74 49 6e 73 74 61 6c 6c 55 6e 6b 6e 6f 77 6e 41 70 70 } //1 requestInstallUnknownApp
		$a_00_3 = {69 73 49 6e 73 74 61 6c 6c 65 64 57 68 6f 57 68 6f } //1 isInstalledWhoWho
		$a_00_4 = {73 74 61 72 74 74 72 61 63 6b 69 6e 67 } //1 starttracking
		$a_00_5 = {69 73 5f 75 70 64 61 74 65 } //1 is_update
		$a_00_6 = {64 6f 77 6e 6c 6f 61 64 57 68 6f 57 68 6f } //1 downloadWhoWho
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}