
rule TrojanSpy_AndroidOS_Twmobo_A{
	meta:
		description = "TrojanSpy:AndroidOS/Twmobo.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {21 53 35 30 10 00 48 03 05 00 21 14 94 04 00 04 48 04 01 04 b7 43 8d 33 4f 03 02 00 d8 00 00 01 } //1
		$a_00_1 = {4e 44 5f 44 55 4d 50 } //1 ND_DUMP
		$a_00_2 = {68 77 69 64 } //1 hwid
		$a_00_3 = {74 72 61 6e 73 70 6f 72 74 20 69 73 20 6f 70 65 6e 20 2d 20 63 6f 6e 6e 65 63 74 69 6e 67 } //1 transport is open - connecting
		$a_00_4 = {67 65 72 65 6e 63 69 61 72 20 61 70 70 73 } //1 gerenciar apps
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}