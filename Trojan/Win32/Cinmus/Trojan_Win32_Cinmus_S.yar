
rule Trojan_Win32_Cinmus_S{
	meta:
		description = "Trojan:Win32/Cinmus.S,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 49 44 5f 31 33 32 39 31 34 37 36 30 32 5f 4d 49 45 45 76 65 6e 74 00 } //01 00 
		$a_01_1 = {5f 7a 63 64 79 5f 73 6d 63 00 } //01 00 
		$a_00_2 = {44 6f 77 6e 6c 6f 61 64 4d 44 35 00 } //01 00 
		$a_00_3 = {44 6f 77 6e 6c 6f 61 64 49 44 00 } //01 00 
		$a_00_4 = {52 65 71 75 65 73 74 4e 65 77 4d 61 69 6e 62 6f 64 79 54 69 6d 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}