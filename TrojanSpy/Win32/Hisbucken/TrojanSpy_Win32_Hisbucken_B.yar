
rule TrojanSpy_Win32_Hisbucken_B{
	meta:
		description = "TrojanSpy:Win32/Hisbucken.B,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 37 00 07 00 00 14 00 "
		
	strings :
		$a_01_0 = {63 00 63 00 6a 00 63 00 6c 00 61 00 73 00 73 00 69 00 66 00 69 00 63 00 61 00 64 00 6f 00 73 00 2e 00 63 00 6f 00 6d 00 } //14 00 
		$a_01_1 = {66 00 6f 00 72 00 6d 00 5f 00 6a 00 5f 00 74 00 61 00 6e 00 63 00 6f 00 64 00 65 00 5f 00 53 00 55 00 42 00 4d 00 49 00 54 00 } //0a 00 
		$a_01_2 = {42 00 43 00 35 00 34 00 42 00 30 00 37 00 36 00 41 00 42 00 41 00 44 00 36 00 38 00 41 00 32 00 37 00 39 00 43 00 38 00 35 00 42 00 41 00 43 00 } //05 00 
		$a_01_3 = {31 00 44 00 30 00 45 00 46 00 37 00 33 00 43 00 44 00 32 00 34 00 43 00 43 00 36 00 35 00 46 00 41 00 37 00 42 00 41 00 36 00 45 00 42 00 43 00 35 00 39 00 45 00 33 00 32 00 30 00 46 00 35 00 34 00 44 00 } //05 00 
		$a_01_4 = {34 00 34 00 44 00 34 00 33 00 34 00 43 00 44 00 35 00 44 00 42 00 46 00 35 00 44 00 42 00 37 00 34 00 33 00 44 00 45 00 33 00 34 00 43 00 39 00 34 00 30 00 43 00 36 00 34 00 41 00 } //05 00 
		$a_01_5 = {33 00 32 00 45 00 41 00 32 00 38 00 46 00 34 00 32 00 35 00 46 00 32 00 31 00 38 00 46 00 36 00 34 00 43 00 43 00 30 00 34 00 30 00 43 00 43 00 } //05 00 
		$a_01_6 = {45 00 32 00 33 00 46 00 44 00 46 00 32 00 42 00 45 00 30 00 37 00 42 00 41 00 37 00 37 00 43 00 38 00 43 00 36 00 41 00 42 00 42 00 38 00 38 00 39 00 43 00 36 00 38 00 42 00 38 00 } //00 00 
	condition:
		any of ($a_*)
 
}