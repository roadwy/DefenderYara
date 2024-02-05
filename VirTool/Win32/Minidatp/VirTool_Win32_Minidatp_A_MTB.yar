
rule VirTool_Win32_Minidatp_A_MTB{
	meta:
		description = "VirTool:Win32/Minidatp.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {ba fd 03 00 ac 41 b8 1f 00 10 00 ff 15 90 01 04 8b d0 48 8d 90 01 05 e8 90 01 04 48 8d 90 01 05 4c 89 6d a0 48 8d 90 01 05 48 89 45 98 e8 90 01 04 f2 0f 10 05 a5 b3 01 00 48 8d 90 01 05 0f b7 05 9f b3 01 00 33 d2 41 b8 fe 01 00 00 90 00 } //01 00 
		$a_03_1 = {48 8b 4c 24 70 ff 15 90 01 04 4c 8b 44 24 78 48 8d 90 01 02 48 89 4c 24 30 41 b9 02 00 00 00 48 8b 4d 80 8b d0 4c 89 6c 24 28 4c 89 6c 24 20 ff 15 90 00 } //01 00 
		$a_03_2 = {ba 04 01 00 00 48 8d 90 01 05 ff 15 90 01 04 4c 8d 90 01 05 ba 04 01 00 00 48 8d 90 01 05 e8 90 01 04 4c 8d 90 01 05 ba 04 01 00 00 48 8d 90 01 05 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}