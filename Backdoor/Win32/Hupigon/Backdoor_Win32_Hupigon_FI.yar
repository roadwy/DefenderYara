
rule Backdoor_Win32_Hupigon_FI{
	meta:
		description = "Backdoor:Win32/Hupigon.FI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 52 41 59 70 49 47 45 4f 4e } //01 00 
		$a_01_1 = {50 4f 73 43 52 45 45 4e 63 45 4e 54 45 52 } //01 00 
		$a_01_2 = {6f 4e 6b 45 59 64 4f 57 4e } //01 00 
		$a_01_3 = {61 55 54 6c 4f 47 49 4e 74 63 70 63 4c 49 45 4e 54 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Hupigon_FI_2{
	meta:
		description = "Backdoor:Win32/Hupigon.FI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {d6 f7 bb fa d7 d4 b6 af c9 cf cf df } //01 00 
		$a_00_1 = {5c 44 65 76 69 63 65 5c 50 68 79 73 69 63 61 6c 4d 65 6d 6f 72 79 } //01 00 
		$a_02_2 = {83 f8 3a 0f 87 90 01 02 00 00 ff 24 85 90 01 03 00 90 00 } //02 00 
		$a_02_3 = {85 c0 0f 84 90 01 02 00 00 c7 85 90 01 02 ff ff 07 00 01 00 90 00 } //01 00 
		$a_00_4 = {00 42 45 49 5f 5a 48 55 00 } //00 00 
	condition:
		any of ($a_*)
 
}