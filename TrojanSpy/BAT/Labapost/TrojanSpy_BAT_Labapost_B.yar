
rule TrojanSpy_BAT_Labapost_B{
	meta:
		description = "TrojanSpy:BAT/Labapost.B,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 6f 70 79 56 69 64 65 6f 5f 52 75 6e 57 6f 72 6b 65 72 43 6f 6d 70 6c 65 74 65 64 } //3 CopyVideo_RunWorkerCompleted
		$a_01_1 = {73 65 74 5f 50 72 6f 63 65 73 73 75 73 55 6e 64 65 74 65 63 74 65 64 } //3 set_ProcessusUndetected
		$a_01_2 = {41 54 53 20 4c 61 62 61 6e 71 75 65 70 6f 73 74 61 6c 65 20 53 74 61 72 74 65 72 2e 65 78 65 } //4 ATS Labanquepostale Starter.exe
		$a_01_3 = {73 65 74 5f 52 41 52 53 74 61 74 75 74 } //4 set_RARStatut
		$a_01_4 = {41 54 53 5f 4c 61 62 61 6e 71 75 65 70 6f 73 74 61 6c 65 5f 53 74 61 72 74 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //5 ATS_Labanquepostale_Starter.Resources.resources
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*5) >=19
 
}