
rule TrojanSpy_Win32_Svelta_A{
	meta:
		description = "TrojanSpy:Win32/Svelta.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {2e 62 61 6e 63 6f 62 72 61 73 69 6c 2e 63 6f 6d 2e 62 72 2f 61 61 70 66 } //01 00 
		$a_01_1 = {48 6f 6f 6b 79 42 48 20 61 74 74 61 63 68 65 64 3a } //01 00 
		$a_01_2 = {73 65 6e 68 61 43 6f 6e 74 61 } //01 00 
		$a_01_3 = {2f 70 6f 73 74 2e 70 68 70 } //01 00 
		$a_01_4 = {50 52 5f 57 72 69 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}