
rule TrojanSpy_AndroidOS_SAgnt_R_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.R!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {75 70 6c 6f 61 64 44 65 76 69 63 65 49 6e 66 6f } //1 uploadDeviceInfo
		$a_01_1 = {6d 65 73 73 61 67 65 54 6f 41 6c 6c 43 6f 6e 74 61 63 74 73 } //1 messageToAllContacts
		$a_01_2 = {63 61 70 74 75 72 65 4d 69 63 72 6f 70 68 6f 6e 65 } //1 captureMicrophone
		$a_01_3 = {63 61 70 74 75 72 65 43 61 6d 65 72 61 4d 61 69 6e } //1 captureCameraMain
		$a_01_4 = {75 70 6c 6f 61 64 43 6f 6e 74 61 63 74 } //1 uploadContact
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}