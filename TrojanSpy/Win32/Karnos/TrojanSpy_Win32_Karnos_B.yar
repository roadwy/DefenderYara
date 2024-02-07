
rule TrojanSpy_Win32_Karnos_B{
	meta:
		description = "TrojanSpy:Win32/Karnos.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 69 65 62 61 5f 6e 61 6d 65 } //01 00  tieba_name
		$a_00_1 = {6d 6f 6e 5f 77 65 62 5f 6b 65 79 77 6f 72 64 } //01 00  mon_web_keyword
		$a_01_2 = {5c 74 61 6f 6a 69 6e 5c 32 2e 30 5c 69 65 73 70 79 } //01 00  \taojin\2.0\iespy
		$a_00_3 = {62 69 6e 67 2e 63 6f 6d 00 00 00 00 67 6f 6f 67 6c 65 00 00 73 6f 67 6f 75 2e 63 6f 6d 00 00 00 73 6f 73 6f 2e 63 6f 6d 00 00 00 00 62 61 69 64 75 2e 63 6f 6d } //01 00 
		$a_02_4 = {74 61 6f 6a 69 6e 2e 63 6f 6d 2f 70 6c 75 67 69 6e 2f 61 63 63 65 70 74 2f 73 65 61 72 63 68 6c 6f 67 90 02 10 64 61 74 61 3d 25 73 00 7b 22 68 6f 73 74 22 3a 25 75 2c 90 02 20 22 6b 65 79 22 3a 22 25 73 22 2c 20 22 69 65 6e 61 6d 65 90 00 } //00 00 
		$a_00_5 = {87 10 00 } //00 00 
	condition:
		any of ($a_*)
 
}