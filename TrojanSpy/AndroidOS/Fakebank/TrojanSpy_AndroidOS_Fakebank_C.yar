
rule TrojanSpy_AndroidOS_Fakebank_C{
	meta:
		description = "TrojanSpy:AndroidOS/Fakebank.C,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 64 65 72 00 } //1
		$a_01_1 = {75 70 6c 6f 61 64 42 61 6e 6b 00 } //1
		$a_01_2 = {61 63 63 6f 75 6e 74 50 73 77 00 } //1
		$a_01_3 = {52 65 73 65 74 69 6e 67 3a } //1 Reseting:
		$a_01_4 = {6d 6f 76 65 74 6f 20 41 43 54 49 56 49 54 59 5f 43 52 45 41 54 45 44 3a } //1 moveto ACTIVITY_CREATED:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}