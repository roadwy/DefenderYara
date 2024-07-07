
rule TrojanSpy_AndroidOS_FakeSecSuit_A{
	meta:
		description = "TrojanSpy:AndroidOS/FakeSecSuit.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 63 74 69 76 61 74 69 6f 6e 49 64 } //1 ActivationId
		$a_01_1 = {41 6c 74 65 72 6e 61 74 69 76 65 20 43 6f 6e 74 72 6f 6c 20 69 73 20 6f 6e 2e 20 57 65 20 63 61 6e 74 20 75 73 65 20 73 63 68 65 64 75 6c 6c 65 72 } //1 Alternative Control is on. We cant use scheduller
		$a_01_2 = {74 6f 3d 25 73 26 69 3d 25 73 26 6d 3d 25 73 26 61 69 64 3d 25 73 26 68 3d 25 73 26 76 3d 25 73 } //1 to=%s&i=%s&m=%s&aid=%s&h=%s&v=%s
		$a_01_3 = {73 65 63 73 75 69 74 65 2e 64 62 } //1 secsuite.db
		$a_01_4 = {47 65 74 41 6e 74 69 76 69 72 75 73 4c 69 6e 6b } //1 GetAntivirusLink
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}