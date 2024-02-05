
rule VirTool_Win32_Reviver_A_MTB{
	meta:
		description = "VirTool:Win32/Reviver.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff 15 5f 4e 01 00 48 8b c8 48 8d 45 a0 48 89 44 24 20 41 b9 90 01 01 00 00 00 4c 8d 45 20 48 8b d7 90 00 } //01 00 
		$a_02_1 = {ff 15 38 4e 01 00 0f b6 45 20 90 01 09 44 24 39 0f b6 45 22 88 44 24 3a 90 01 09 b6 45 24 88 44 24 30 0f b6 45 25 88 44 24 31 90 02 10 45 27 88 44 24 33 48 63 90 02 10 34 33 49 8d 4e 09 90 00 } //01 00 
		$a_00_2 = {48 8d 15 27 ce 01 00 48 8b c8 ff 15 56 4a 01 00 48 85 c0 75 09 48 8d 0d 22 ce 01 00 eb 25 } //00 00 
	condition:
		any of ($a_*)
 
}