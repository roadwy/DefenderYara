
rule TrojanSpy_BAT_Quoler_A{
	meta:
		description = "TrojanSpy:BAT/Quoler.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 00 56 00 52 00 6d 00 4d 00 6d 00 51 00 61 00 31 00 45 00 59 00 } //1 RVRmMmQa1EY
		$a_01_1 = {6f 00 6f 00 66 00 66 00 69 00 63 00 65 00 32 00 38 00 37 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //1 ooffice287@gmail.com
		$a_01_2 = {69 00 6e 00 66 00 6f 00 40 00 74 00 68 00 65 00 61 00 64 00 76 00 65 00 72 00 74 00 69 00 73 00 65 00 72 00 2e 00 62 00 69 00 7a 00 } //1 info@theadvertiser.biz
		$a_01_3 = {51 00 75 00 6f 00 74 00 61 00 74 00 69 00 6f 00 6e 00 31 00 30 00 32 00 31 00 30 00 20 00 73 00 74 00 61 00 72 00 74 00 65 00 64 00 20 00 61 00 74 00 3a 00 20 00 } //1 Quotation10210 started at: 
		$a_01_4 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
		$a_01_5 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 54 00 6f 00 6f 00 6c 00 73 00 } //1 DisableRegistryTools
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}