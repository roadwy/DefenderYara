
rule Trojan_Win32_Tapaoux_A{
	meta:
		description = "Trojan:Win32/Tapaoux.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c7 8a 0e 99 f7 7c 24 10 8a 54 14 14 3a ca 74 02 32 ca 88 0c 33 47 46 3b fd 7c e4 } //01 00 
		$a_01_1 = {64 a1 30 00 00 00 0f b6 40 68 83 e0 70 85 c0 74 07 } //01 00 
		$a_01_2 = {50 6c 61 79 53 50 5f 64 6c 6c 2e 64 6c 6c 00 4d 65 6d 6f 72 79 41 6c 6c 6f 63 45 72 72 6f 72 00 } //01 00  汐祡偓摟汬搮汬䴀浥牯䅹汬捯牅潲r
		$a_00_3 = {25 73 5c 25 73 2e 64 6c 6c } //01 00  %s\%s.dll
		$a_00_4 = {25 73 5c 25 73 2e 73 79 73 } //01 00  %s\%s.sys
		$a_00_5 = {25 73 5c 25 73 2e 6c 6e 6b } //00 00  %s\%s.lnk
	condition:
		any of ($a_*)
 
}