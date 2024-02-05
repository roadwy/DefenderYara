
rule TrojanSpy_Win32_Pexnod_B{
	meta:
		description = "TrojanSpy:Win32/Pexnod.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 41 4f 4c 43 6c 69 70 62 6f 61 72 64 } //01 00 
		$a_01_1 = {6d 6f 64 53 6f 6c 69 74 61 69 72 65 47 61 6d 65 } //01 00 
		$a_01_2 = {43 6f 6c 6f 72 20 53 70 79 20 33 2e 30 } //01 00 
		$a_01_3 = {66 61 63 75 6c 74 79 6c 6f 67 69 6e } //01 00 
		$a_01_4 = {62 6f 64 79 20 6f 6e 6c 6f 61 64 3d 22 64 6f 63 75 6d 65 6e 74 2e 66 6f 72 6d 73 5b 30 5d 2e 73 75 62 6d 69 74 } //00 00 
	condition:
		any of ($a_*)
 
}