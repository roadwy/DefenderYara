
rule TrojanSpy_AndroidOS_Abarw_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Abarw.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 72 61 62 57 61 72 65 53 4d 53 } //1 ArabWareSMS
		$a_01_1 = {5f 72 65 61 6c 5f 74 69 6d 65 5f 63 68 65 63 6b } //1 _real_time_check
		$a_01_2 = {5f 73 74 61 72 74 5f 61 74 74 61 63 6b } //1 _start_attack
		$a_01_3 = {2f 73 65 6e 64 4d 65 73 73 61 67 65 3f 63 68 61 74 5f 69 64 3d } //1 /sendMessage?chat_id=
		$a_01_4 = {6c 69 73 74 4d 61 70 44 61 74 61 } //1 listMapData
		$a_01_5 = {67 65 74 44 69 73 70 6c 61 79 4d 65 73 73 61 67 65 42 6f 64 79 } //1 getDisplayMessageBody
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}