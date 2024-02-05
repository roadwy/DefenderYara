
rule TrojanSpy_Win32_Ambler_L{
	meta:
		description = "TrojanSpy:Win32/Ambler.L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {0a 5b 25 73 5d 0a 4b 45 59 4c 4f 47 47 45 44 3a 25 73 0a 00 } //01 00 
		$a_00_1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 20 49 6e 73 74 6c 6c 48 } //01 00 
		$a_01_2 = {8b 45 08 8b cf 2b c7 8b d6 8a 1c 08 80 f3 0e 88 19 41 4a 75 f4 } //00 00 
	condition:
		any of ($a_*)
 
}