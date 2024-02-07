
rule TrojanSpy_BAT_Blanajog_A{
	meta:
		description = "TrojanSpy:BAT/Blanajog.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6e 6a 4c 6f 67 67 65 72 } //01 00  njLogger
		$a_01_1 = {00 4c 61 73 74 41 56 00 } //01 00  䰀獡䅴V
		$a_01_2 = {00 4c 61 73 74 41 53 00 } //01 00  䰀獡䅴S
		$a_01_3 = {00 57 52 4b 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_BAT_Blanajog_A_2{
	meta:
		description = "TrojanSpy:BAT/Blanajog.A,SIGNATURE_TYPE_PEHSTR_EXT,2b 00 2b 00 09 00 00 0a 00 "
		
	strings :
		$a_00_0 = {6e 6a 4c 6f 67 67 65 72 } //0a 00  njLogger
		$a_01_1 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //0a 00  GetAsyncKeyState
		$a_01_2 = {4b 42 44 4c 4c 48 4f 4f 4b 53 54 52 55 43 54 } //0a 00  KBDLLHOOKSTRUCT
		$a_01_3 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //01 00  CallNextHookEx
		$a_01_4 = {4c 61 73 74 41 56 00 } //01 00 
		$a_01_5 = {4c 61 73 74 41 53 00 } //01 00 
		$a_01_6 = {57 52 4b 00 } //01 00  剗K
		$a_01_7 = {5b 00 45 00 4e 00 54 00 45 00 52 00 5d 00 } //01 00  [ENTER]
		$a_01_8 = {5b 00 54 00 41 00 50 00 5d 00 } //00 00  [TAP]
		$a_00_9 = {5d 04 00 00 d1 20 03 80 5c 22 00 00 d2 20 03 80 00 00 01 00 27 00 0c 00 cb 01 42 6c 61 6e 61 6a 6f 67 2e 42 00 00 01 40 } //05 82 
	condition:
		any of ($a_*)
 
}