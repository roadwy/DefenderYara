
rule Trojan_AndroidOS_Kylk_J{
	meta:
		description = "Trojan:AndroidOS/Kylk.J,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 54 44 41 64 6d 52 69 76 65 72 } //2 CTDAdmRiver
		$a_01_1 = {63 6f 6d 5f 70 72 65 5f 72 65 67 } //2 com_pre_reg
		$a_01_2 = {64 6c 61 63 5f 6c 6e 67 } //2 dlac_lng
		$a_01_3 = {44 78 6c 64 5f 61 70 70 } //2 Dxld_app
		$a_01_4 = {72 65 71 43 6f 61 4c 6f 63 } //2 reqCoaLoc
		$a_01_5 = {72 65 71 52 65 63 65 53 6d 73 } //2 reqReceSms
		$a_01_6 = {57 41 5f 41 55 44 49 4f 5f 54 49 4d 45 5f 53 45 4e 44 } //2 WA_AUDIO_TIME_SEND
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=6
 
}