
rule TrojanSpy_Win32_Ambler_R{
	meta:
		description = "TrojanSpy:Win32/Ambler.R,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {40 40 3b 45 fc 73 69 0f be 45 f8 50 8b 45 08 03 45 f4 0f be 00 50 e8 } //02 00 
		$a_01_1 = {2a 2a 2a 2a 2a 2a 2a 47 52 41 42 42 45 44 20 42 41 4c 41 4e 43 45 2a 2a 2a 2a 2a 2a 2a } //01 00 
		$a_01_2 = {5c 79 79 74 78 74 74 00 5c 63 74 6f 00 } //01 00 
		$a_03_3 = {69 65 78 70 6c 6f 72 65 2e 65 00 90 02 05 69 72 65 66 6f 78 2e 65 00 90 02 05 72 75 6e 64 6c 6c 33 32 2e 65 00 90 00 } //01 00 
		$a_01_4 = {00 6e 6f 6c 6f 67 00 00 00 61 62 00 00 64 6d 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}