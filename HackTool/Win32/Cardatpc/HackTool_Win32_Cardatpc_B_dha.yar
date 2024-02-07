
rule HackTool_Win32_Cardatpc_B_dha{
	meta:
		description = "HackTool:Win32/Cardatpc.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {46 81 e6 ff 00 00 00 0f b6 44 31 08 03 f8 81 e7 ff 00 00 00 0f b6 5c 39 08 88 5c 31 08 88 44 39 08 02 c3 8b 5d fc 0f b6 c0 8a 44 08 08 32 04 13 42 ff 4d 08 88 42 ff } //01 00 
		$a_01_1 = {8a 4e 01 83 c4 04 80 3e 31 } //01 00 
		$a_01_2 = {81 3a 21 21 21 21 } //01 00 
		$a_01_3 = {63 6c 65 61 6e 6c 61 73 74 2d 71 75 69 74 20 3c 31 7c 30 3e } //01 00  cleanlast-quit <1|0>
		$a_01_4 = {3c 50 49 44 3a 55 53 45 52 3a 44 4f 4d 41 49 4e 3a 4e 54 4c 4d 3e } //01 00  <PID:USER:DOMAIN:NTLM>
		$a_01_5 = {5c 5c 2e 5c 70 69 70 65 5c 6c 73 61 73 73 70 } //00 00  \\.\pipe\lsassp
	condition:
		any of ($a_*)
 
}