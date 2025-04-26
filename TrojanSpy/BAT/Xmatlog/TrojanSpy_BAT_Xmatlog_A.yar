
rule TrojanSpy_BAT_Xmatlog_A{
	meta:
		description = "TrojanSpy:BAT/Xmatlog.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {5b 00 78 00 4d 00 61 00 74 00 65 00 72 00 64 00 6f 00 6d 00 5d 00 } //1 [xMaterdom]
		$a_01_1 = {2f 00 43 00 20 00 6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 20 00 4d 00 70 00 73 00 53 00 76 00 63 00 } //1 /C net stop MpsSvc
		$a_01_2 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 54 00 6f 00 6f 00 6c 00 73 00 } //1 DisableRegistryTools
		$a_01_3 = {4d 00 61 00 74 00 65 00 72 00 2d 00 4c 00 6f 00 67 00 67 00 65 00 72 00 2d 00 4c 00 6f 00 67 00 } //1 Mater-Logger-Log
		$a_01_4 = {78 4d 61 74 65 72 4c 6f 67 67 65 72 5f 53 74 75 62 } //1 xMaterLogger_Stub
		$a_01_5 = {73 79 33 32 6b 6f 70 79 61 6c 61 6d 61 6d 65 74 6f 64 } //1 sy32kopyalamametod
		$a_01_6 = {4c 6f 67 6c 61 72 69 67 6f 6e 64 65 72 } //1 Loglarigonder
		$a_01_7 = {72 65 67 65 6e 67 65 6c 6c 65 6d 65 6d 65 74 6f 64 75 } //1 regengellememetodu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=6
 
}