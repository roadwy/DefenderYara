
rule TrojanSpy_Win32_Dofoil_A{
	meta:
		description = "TrojanSpy:Win32/Dofoil.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 73 6e 69 66 66 65 72 73 2e 70 68 70 } //01 00 
		$a_00_1 = {40 3f 0d 0a 53 65 72 76 65 72 3a 20 3f 20 28 } //01 00 
		$a_01_2 = {8b f8 8a 0f 80 f9 0d 74 12 80 f9 0a 74 0d 84 c9 74 09 8a 4f 01 47 80 f9 0d 75 ee } //00 00 
	condition:
		any of ($a_*)
 
}