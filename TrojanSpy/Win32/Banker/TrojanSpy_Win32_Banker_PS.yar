
rule TrojanSpy_Win32_Banker_PS{
	meta:
		description = "TrojanSpy:Win32/Banker.PS,SIGNATURE_TYPE_PEHSTR,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00 
		$a_01_1 = {2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 20 43 41 54 41 4c 55 4e 59 41 20 2d 20 54 68 75 6e 64 33 72 43 34 73 48 20 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a } //01 00 
		$a_01_2 = {43 3a 41 3a 54 3a 41 3a 4c 3a 55 3a 4e 3a 59 3a 41 } //01 00 
		$a_01_3 = {43 30 44 2d 55 53 55 34 52 31 30 31 3a 20 } //01 00 
		$a_01_4 = {43 4c 56 2d 34 43 33 35 35 30 31 3a 20 } //00 00 
	condition:
		any of ($a_*)
 
}