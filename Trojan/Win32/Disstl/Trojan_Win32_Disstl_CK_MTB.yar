
rule Trojan_Win32_Disstl_CK_MTB{
	meta:
		description = "Trojan:Win32/Disstl.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 68 34 78 30 72 5c 44 69 73 63 6f 72 64 2d 54 6f 6b 65 6e 2d 47 72 61 62 62 65 72 2d 6d 61 73 74 65 72 5c 52 65 6c 65 61 73 65 5c 54 6f 6b 65 6e 2d 44 69 73 63 2e 70 64 62 } //01 00  C:\h4x0r\Discord-Token-Grabber-master\Release\Token-Disc.pdb
		$a_01_1 = {64 69 73 63 6f 72 64 2e 63 6f 6d } //01 00  discord.com
		$a_01_2 = {4c 6f 6f 70 3f 3f } //01 00  Loop??
		$a_01_3 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_5 = {64 69 73 63 6f 72 64 70 74 62 } //01 00  discordptb
		$a_01_6 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //01 00  GetTickCount
		$a_01_7 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //00 00  QueryPerformanceCounter
	condition:
		any of ($a_*)
 
}