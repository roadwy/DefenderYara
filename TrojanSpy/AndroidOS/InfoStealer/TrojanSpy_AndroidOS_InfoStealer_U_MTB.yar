
rule TrojanSpy_AndroidOS_InfoStealer_U_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.U!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {2f 72 61 74 6a 73 [0-02] 2f 54 6f 6f 6c 73 2f 52 75 6e 55 74 69 6c 3b } //2
		$a_00_1 = {4c 6d 65 2f 65 76 65 72 79 74 68 69 6e 67 2f 70 72 6f 76 69 64 65 72 73 2f } //2 Lme/everything/providers/
		$a_01_2 = {67 65 74 43 61 6c 6c 4c 6f 67 } //1 getCallLog
		$a_01_3 = {67 65 74 53 4d 53 } //1 getSMS
		$a_01_4 = {67 65 74 41 6c 6c 41 70 70 73 } //1 getAllApps
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}