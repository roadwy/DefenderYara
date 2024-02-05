
rule Backdoor_Win32_Thoper_F_dha{
	meta:
		description = "Backdoor:Win32/Thoper.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 00 69 00 6e 00 73 00 74 00 61 00 30 00 5c 00 64 00 65 00 66 00 61 00 75 00 6c 00 74 00 } //01 00 
		$a_01_1 = {52 00 55 00 4e 00 41 00 53 00 } //01 00 
		$a_00_2 = {c1 e1 0c 0f b6 11 83 fa 4d 75 3c 8b 45 ec c1 e0 0c 0f b6 48 01 83 f9 5a 75 2d 8b 55 ec c1 e2 0c 0f b6 42 02 3d 90 00 00 00 75 1c 8b 4d ec c1 e1 0c } //00 00 
	condition:
		any of ($a_*)
 
}