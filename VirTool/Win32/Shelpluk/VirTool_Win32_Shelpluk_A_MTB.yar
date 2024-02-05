
rule VirTool_Win32_Shelpluk_A_MTB{
	meta:
		description = "VirTool:Win32/Shelpluk.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 1c 86 40 3b c2 90 01 02 8d 90 01 06 3b cf 73 0b 30 1c 31 8d 90 01 02 41 3b cf 90 00 } //01 00 
		$a_03_1 = {c6 45 fc 06 8b 45 c4 2b c6 6a 04 89 45 c4 40 68 00 10 00 00 50 53 89 45 ec ff 15 90 01 04 8b c8 89 4d c0 85 c9 90 00 } //01 00 
		$a_03_2 = {6a 00 6a 00 ff 75 c0 89 75 e4 68 70 1c 40 00 6a 00 6a 00 ff 15 90 01 04 8b d8 85 db 90 00 } //01 00 
		$a_03_3 = {50 6a 40 6a 07 57 ff 15 90 01 04 85 c0 90 01 02 8b 45 ec 89 07 66 8b 45 f0 66 89 47 04 8a 45 f6 88 47 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}