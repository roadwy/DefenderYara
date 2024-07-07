
rule TrojanSpy_AndroidOS_Ahmyth_D{
	meta:
		description = "TrojanSpy:AndroidOS/Ahmyth.D,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 2e 53 79 73 74 65 6d 2f 43 74 2e 63 73 76 2f } //1 /.System/Ct.csv/
		$a_00_1 = {49 6e 74 72 6f 53 63 72 65 65 6e 5f 41 63 74 69 76 69 74 79 } //1 IntroScreen_Activity
		$a_00_2 = {6c 6f 67 6b 33 79 2e 74 78 74 } //1 logk3y.txt
		$a_00_3 = {2f 2e 53 79 73 74 65 6d 2f 73 6d 2e 63 73 76 2f } //1 /.System/sm.csv/
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}