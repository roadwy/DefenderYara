
rule TrojanSpy_Win32_Bancos_AJQ{
	meta:
		description = "TrojanSpy:Win32/Bancos.AJQ,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 69 74 65 50 61 72 61 45 6e 76 69 6f } //03 00 
		$a_01_1 = {50 49 44 6a 63 69 74 61 } //03 00 
		$a_01_2 = {74 72 61 76 61 5f 6d 6f 75 73 65 54 69 6d 65 72 } //03 00 
		$a_01_3 = {6d 00 61 00 6e 00 64 00 61 00 2e 00 70 00 68 00 70 00 } //00 00 
		$a_00_4 = {5d 04 00 00 6b 06 } //03 80 
	condition:
		any of ($a_*)
 
}