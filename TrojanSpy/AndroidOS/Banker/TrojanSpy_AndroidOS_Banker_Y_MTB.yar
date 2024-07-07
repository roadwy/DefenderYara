
rule TrojanSpy_AndroidOS_Banker_Y_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.Y!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 74 2f 77 6f 72 6b 2f 61 63 74 69 76 69 74 79 2f 4c 6f 67 69 6e 41 63 74 } //1 mt/work/activity/LoginAct
		$a_01_1 = {41 6c 62 75 6d 53 65 72 76 69 63 65 } //1 AlbumService
		$a_01_2 = {4c 6f 63 61 6c 43 61 6c 6c 4d 74 } //1 LocalCallMt
		$a_01_3 = {4c 6f 63 61 6c 4d 73 67 4d 74 } //1 LocalMsgMt
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}