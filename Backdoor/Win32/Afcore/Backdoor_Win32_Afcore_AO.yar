
rule Backdoor_Win32_Afcore_AO{
	meta:
		description = "Backdoor:Win32/Afcore.AO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 02 3d a1 00 00 00 74 1c 8b 0d 90 01 02 00 10 0f b6 11 81 fa eb 00 00 00 74 0b c7 05 90 01 03 10 90 01 04 cc c7 45 fc 00 00 00 00 eb 09 8b 45 fc 83 c0 01 89 45 fc 83 7d fc 12 90 00 } //01 00 
		$a_00_1 = {00 6a 66 75 6e 79 00 00 00 5c 73 79 73 74 65 6d 33 32 5c 73 70 6f 6f 6c 00 73 76 2e 65 78 65 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}