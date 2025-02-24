
rule TrojanSpy_AndroidOS_GossRat_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/GossRat.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 73 61 64 65 65 72 2f 6d 61 6c 6c } //1 com/sadeer/mall
		$a_01_1 = {67 65 74 43 61 6c 6c 4c 6f 67 73 } //1 getCallLogs
		$a_01_2 = {73 61 64 65 72 61 74 } //1 saderat
		$a_03_3 = {74 74 70 73 3a 2f 2f [0-10] 2e 62 69 67 6f 70 61 79 2e 77 6f 72 6b 65 72 73 2e 64 65 76 2f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}