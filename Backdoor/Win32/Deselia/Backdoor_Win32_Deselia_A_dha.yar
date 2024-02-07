
rule Backdoor_Win32_Deselia_A_dha{
	meta:
		description = "Backdoor:Win32/Deselia.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {5c 30 30 30 45 4c 49 53 45 90 02 08 2e 54 4d 50 90 00 } //01 00 
		$a_00_1 = {45 6c 69 73 65 44 4c 4c 2e 64 6c 6c } //01 00  EliseDLL.dll
		$a_01_2 = {45 53 45 6e 74 72 79 00 45 53 48 61 6e 64 6c 65 00 } //02 00 
		$a_01_3 = {25 7f 00 00 80 79 05 48 83 c8 80 40 30 06 47 } //01 00 
		$a_01_4 = {53 bb 00 00 00 00 b8 01 00 00 00 0f 3f 07 0b 85 db 0f 94 45 e7 5b } //01 00 
		$a_00_5 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 } //00 00 
	condition:
		any of ($a_*)
 
}