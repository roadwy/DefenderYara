
rule TrojanSpy_Win32_Mrophine_A_bit{
	meta:
		description = "TrojanSpy:Win32/Mrophine.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 00 43 00 4c 00 49 00 50 00 42 00 4f 00 41 00 52 00 44 00 20 00 45 00 4e 00 44 00 5d 00 } //01 00 
		$a_01_1 = {53 00 74 00 61 00 74 00 75 00 73 00 3a 00 20 00 6d 00 6f 00 72 00 70 00 68 00 69 00 6e 00 45 00 00 00 } //01 00 
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c } //00 00 
	condition:
		any of ($a_*)
 
}