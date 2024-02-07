
rule Trojan_Win32_Hokobot_B_dll{
	meta:
		description = "Trojan:Win32/Hokobot.B.dll!dha,SIGNATURE_TYPE_PEHSTR_EXT,68 00 68 00 05 00 00 64 00 "
		
	strings :
		$a_01_0 = {5c 50 72 6f 66 69 6c 65 72 2d 50 5c 53 6d 61 72 74 53 65 6e 64 65 72 5c 77 6e 68 65 6c 70 } //01 00  \Profiler-P\SmartSender\wnhelp
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 50 49 44 20 00 00 00 4d 45 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00 
		$a_01_2 = {46 64 6f 77 6e } //01 00  Fdown
		$a_01_3 = {49 6e 65 74 52 65 61 64 46 } //01 00  InetReadF
		$a_01_4 = {50 61 74 68 50 72 6f 63 65 73 73 } //00 00  PathProcess
		$a_00_5 = {5d 04 00 00 } //47 33 
	condition:
		any of ($a_*)
 
}