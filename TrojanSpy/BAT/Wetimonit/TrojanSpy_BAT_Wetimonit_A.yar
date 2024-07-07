
rule TrojanSpy_BAT_Wetimonit_A{
	meta:
		description = "TrojanSpy:BAT/Wetimonit.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 65 74 00 63 66 00 70 61 73 73 00 52 75 6e 41 53 53 } //6 敷t晣瀀獡s畒䅮卓
		$a_01_1 = {61 64 64 5f 53 68 75 74 64 6f 77 6e 00 45 78 69 74 } //2
		$a_01_2 = {49 45 4d 6f 6e 69 74 6f 72 00 49 45 4d 6f 6e 69 74 6f 72 2e 65 78 65 } //2
		$a_01_3 = {6f 62 6a 5c 52 65 6c 65 61 73 65 5c 49 45 4d 6f 6e 69 74 6f 72 } //2 obj\Release\IEMonitor
		$a_01_4 = {73 65 74 5f 53 68 6f 77 49 6e 54 61 73 6b 62 61 72 00 73 65 74 5f 4f 70 61 63 69 74 79 } //1
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=9
 
}