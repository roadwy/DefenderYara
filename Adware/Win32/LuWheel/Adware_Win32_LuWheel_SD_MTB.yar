
rule Adware_Win32_LuWheel_SD_MTB{
	meta:
		description = "Adware:Win32/LuWheel.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {6b 69 6c 6c 2e 62 61 74 } //01 00 
		$a_81_1 = {4c 75 63 6b 79 57 68 65 65 6c 31 } //01 00 
		$a_81_2 = {4c 75 63 6b 79 20 4a 6f 65 } //01 00 
		$a_81_3 = {63 3a 5c 55 73 65 72 73 5c 77 69 6e 2e 74 78 74 } //01 00 
		$a_81_4 = {4b 69 6c 6c 50 72 6f 63 44 4c 4c 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}