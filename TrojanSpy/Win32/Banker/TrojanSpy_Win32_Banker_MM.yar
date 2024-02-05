
rule TrojanSpy_Win32_Banker_MM{
	meta:
		description = "TrojanSpy:Win32/Banker.MM,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 6f 67 69 6e 5f 4f 6e 43 6c 69 63 6b } //01 00 
		$a_00_1 = {73 65 6e 68 61 20 64 65 20 61 63 65 73 73 6f } //01 00 
		$a_01_2 = {50 4f 53 54 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 3a } //01 00 
		$a_01_3 = {7e 2f 7e 2f 7e 2f 7e 43 68 65 67 6f 75 } //01 00 
		$a_02_4 = {68 74 74 70 73 3a 2f 2f 90 02 20 2e 63 6f 6d 2e 62 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}