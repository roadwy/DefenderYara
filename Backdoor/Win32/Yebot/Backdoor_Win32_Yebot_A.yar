
rule Backdoor_Win32_Yebot_A{
	meta:
		description = "Backdoor:Win32/Yebot.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {c6 04 06 e9 8b 45 f4 8b 0f 83 e8 05 89 44 0e 01 6a 08 8d 46 40 50 8d be a8 01 00 00 57 e8 90 01 04 83 c4 0c c6 07 fa ff 37 ff b6 80 00 00 00 ff 15 90 00 } //01 00 
		$a_01_1 = {54 48 49 53 5f 53 54 52 49 4e 47 5f 49 53 5f 55 52 4c 5f 52 43 34 5f 4b 45 59 00 } //01 00 
		$a_00_2 = {48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 } //01 00  HARDWARE\DESCRIPTION\System\CentralProcessor\0
		$a_01_3 = {47 6c 6f 62 61 6c 5c 73 73 5f 65 76 74 2d 25 } //01 00  Global\ss_evt-%
		$a_01_4 = {25 42 4f 54 49 44 25 } //00 00  %BOTID%
	condition:
		any of ($a_*)
 
}