
rule TrojanSpy_AndroidOS_Capchator_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Capchator.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2e 72 75 2f 43 61 70 74 63 68 61 74 6f 72 2e 61 70 6b } //2 .ru/Captchator.apk
		$a_00_1 = {4c 6f 61 64 42 61 6e 6b 65 72 } //1 LoadBanker
		$a_00_2 = {49 6e 73 74 61 6c 6c 65 64 42 61 6e 6b 73 } //1 InstalledBanks
		$a_00_3 = {70 6d 20 69 6e 73 74 61 6c 6c } //1 pm install
		$a_00_4 = {55 70 6c 6f 61 64 46 69 6c 65 54 6f 55 72 6c 41 6e 64 44 65 6c } //1 UploadFileToUrlAndDel
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}