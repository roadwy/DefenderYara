
rule Backdoor_Win32_Thoper_E{
	meta:
		description = "Backdoor:Win32/Thoper.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 7d fc 5a 7e 09 b8 cc cc cc cc ff d0 } //01 00 
		$a_03_1 = {83 ec 08 83 3d 90 01 04 00 75 3a 68 90 01 04 68 90 01 04 6a 90 01 01 68 90 01 04 8d 4d f8 e8 90 01 04 8b c8 e8 90 01 04 50 a1 90 01 04 50 ff 15 90 01 04 a3 90 01 04 8d 4d f8 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}