
rule Backdoor_Win32_Zbot_C_MTB{
	meta:
		description = "Backdoor:Win32/Zbot.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 44 14 28 8b 4c 24 24 32 c8 88 4c 14 28 42 83 fa 90 01 01 72 ec 90 00 } //01 00 
		$a_03_1 = {8a 44 0c 0c 2c 90 01 01 88 44 0c 0c 41 83 f9 90 01 01 72 f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}