
rule Backdoor_Win32_Tofsee_BK_MTB{
	meta:
		description = "Backdoor:Win32/Tofsee.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {89 45 0c 8b 45 e4 01 45 0c 8b 45 0c 33 45 f8 33 c8 89 4d ec 8b 45 ec 29 45 08 81 45 f4 90 02 04 ff 4d f0 8b 45 08 0f 85 90 00 } //01 00 
		$a_01_1 = {03 c8 8b d0 c1 ea 05 03 55 e0 c1 e0 04 03 45 e8 89 4d f8 33 d0 33 d1 89 55 0c } //01 00 
		$a_01_2 = {81 ff 6e 27 87 01 7f 0d 47 81 ff f6 ea 2b 33 0f 8c } //00 00 
	condition:
		any of ($a_*)
 
}