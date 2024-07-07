
rule TrojanSpy_AndroidOS_Spynote_K_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Spynote.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6b 65 79 5f 6c 6f 67 67 65 72 5f 6f 6e 6c 69 6e 65 5f 73 74 61 72 74 } //1 key_logger_online_start
		$a_01_1 = {63 61 6d 65 72 61 5f 6d 61 6e 61 67 65 72 5f 63 61 70 74 75 72 65 } //1 camera_manager_capture
		$a_01_2 = {53 65 6e 64 5f 53 65 72 76 65 72 30 30 30 } //1 Send_Server000
		$a_01_3 = {73 70 79 61 6e 64 72 6f 69 64 } //1 spyandroid
		$a_01_4 = {73 68 65 6c 6c 5f 74 65 72 6d 69 6e 61 6c } //1 shell_terminal
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}