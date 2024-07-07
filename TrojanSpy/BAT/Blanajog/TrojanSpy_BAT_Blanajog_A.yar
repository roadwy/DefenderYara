
rule TrojanSpy_BAT_Blanajog_A{
	meta:
		description = "TrojanSpy:BAT/Blanajog.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6e 6a 4c 6f 67 67 65 72 } //1 njLogger
		$a_01_1 = {00 4c 61 73 74 41 56 00 } //1 䰀獡䅴V
		$a_01_2 = {00 4c 61 73 74 41 53 00 } //1 䰀獡䅴S
		$a_01_3 = {00 57 52 4b 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanSpy_BAT_Blanajog_A_2{
	meta:
		description = "TrojanSpy:BAT/Blanajog.A,SIGNATURE_TYPE_PEHSTR_EXT,2b 00 2b 00 09 00 00 "
		
	strings :
		$a_00_0 = {6e 6a 4c 6f 67 67 65 72 } //10 njLogger
		$a_01_1 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //10 GetAsyncKeyState
		$a_01_2 = {4b 42 44 4c 4c 48 4f 4f 4b 53 54 52 55 43 54 } //10 KBDLLHOOKSTRUCT
		$a_01_3 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //10 CallNextHookEx
		$a_01_4 = {4c 61 73 74 41 56 00 } //1
		$a_01_5 = {4c 61 73 74 41 53 00 } //1
		$a_01_6 = {57 52 4b 00 } //1 剗K
		$a_01_7 = {5b 00 45 00 4e 00 54 00 45 00 52 00 5d 00 } //1 [ENTER]
		$a_01_8 = {5b 00 54 00 41 00 50 00 5d 00 } //1 [TAP]
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=43
 
}