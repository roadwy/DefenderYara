
rule Backdoor_Win32_Caphaw_Z{
	meta:
		description = "Backdoor:Win32/Caphaw.Z,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {89 44 24 08 89 44 24 04 8b 44 24 04 83 c4 04 3d 00 00 90 01 01 01 73 2c e8 90 01 02 00 00 89 44 24 08 db 44 24 08 d9 fa e8 90 01 02 00 00 03 44 24 04 89 44 24 04 8b 0c 24 41 90 00 } //01 00 
		$a_01_1 = {8b 47 3c 8b 74 38 28 03 f7 83 c4 04 89 75 d8 ff d6 8b 5d d8 93 90 cc } //01 00 
		$a_01_2 = {8b 43 3c 8b 4c 18 28 83 c4 04 03 cb ff d1 } //00 00 
	condition:
		any of ($a_*)
 
}