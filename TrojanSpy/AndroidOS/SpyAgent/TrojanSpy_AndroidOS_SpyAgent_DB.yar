
rule TrojanSpy_AndroidOS_SpyAgent_DB{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgent.DB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {77 64 73 79 6e 63 65 72 5f 63 6f 6e 66 69 67 5f 64 61 74 61 42 61 73 65 } //2 wdsyncer_config_dataBase
		$a_00_1 = {73 65 74 44 65 66 4d 73 67 } //1 setDefMsg
		$a_00_2 = {72 65 63 2d } //1 rec-
		$a_00_3 = {73 65 6e 74 46 69 6c 65 } //1 sentFile
		$a_00_4 = {75 70 6c 6f 61 64 46 69 6c 65 } //1 uploadFile
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}