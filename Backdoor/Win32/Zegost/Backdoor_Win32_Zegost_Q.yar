
rule Backdoor_Win32_Zegost_Q{
	meta:
		description = "Backdoor:Win32/Zegost.Q,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b c1 be 0a 00 00 00 99 f7 fe 8a 82 90 01 04 8a 91 90 01 04 32 d0 88 91 90 01 04 41 81 f9 90 01 03 00 7c d9 90 00 } //01 00 
		$a_01_1 = {25 73 5c 6d 74 25 78 6d 2e 64 6c 6c } //01 00  %s\mt%xm.dll
		$a_01_2 = {25 73 5c 6e 74 25 78 7a 2e 64 6c 6c } //00 00  %s\nt%xz.dll
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Zegost_Q_2{
	meta:
		description = "Backdoor:Win32/Zegost.Q,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {25 2d 32 34 73 20 25 2d 31 35 73 } //%-24s %-15s  01 00 
		$a_03_1 = {b9 00 08 00 00 33 c0 8d bc 24 90 01 02 00 00 50 f3 ab 8b 83 90 01 01 00 00 00 8d 94 24 90 01 02 00 00 68 00 20 00 00 52 50 ff d5 85 c0 7e 90 01 01 8d 8c 24 90 1b 00 00 00 50 51 90 00 } //01 00 
		$a_03_2 = {57 50 ff b6 90 01 01 00 00 00 ff 15 90 01 04 80 bd 90 01 02 ff ff 05 0f 85 90 01 02 00 00 38 9d 90 01 02 ff ff 74 0d 80 bd 90 1b 04 ff ff 02 0f 85 90 01 02 00 00 80 bd 90 1b 04 ff ff 02 0f 85 90 01 02 00 00 68 90 01 04 e8 90 01 04 85 c0 59 0f 86 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}