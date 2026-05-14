
rule Trojan_Win32_ShellCodeRunner_KK_MTB{
	meta:
		description = "Trojan:Win32/ShellCodeRunner.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c0 23 6a 02 59 6b c9 2f 66 89 81 ?? ?? ?? ?? 6a 02 58 6b c0 2f 0f b7 80 ?? ?? ?? ?? 83 e8 07 6a 02 59 6b c9 30 } //20
		$a_01_1 = {79 79 78 66 5f 70 6c 61 79 2e 64 6c 6c } //10 yyxf_play.dll
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_Win32_ShellCodeRunner_KK_MTB_2{
	meta:
		description = "Trojan:Win32/ShellCodeRunner.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 44 8c 2c 03 44 24 0c 41 89 44 24 0c 83 f9 04 7c ee } //20
		$a_01_1 = {8b 44 24 10 23 c7 01 44 24 14 d1 7c 24 10 83 7c 24 14 03 } //10
		$a_01_2 = {8b 44 8c 24 03 44 24 10 41 89 44 24 10 83 f9 03 7c ee } //5
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}
rule Trojan_Win32_ShellCodeRunner_KK_MTB_3{
	meta:
		description = "Trojan:Win32/ShellCodeRunner.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 0a 8d 52 04 33 4a f8 81 e1 ff ff ff 7f 33 4a f8 8b c1 24 01 0f b6 c0 f7 d8 1b c0 d1 e9 25 df b0 08 99 33 82 2c 06 00 00 33 c1 89 82 b8 09 00 00 83 ef 01 } //3
		$a_03_1 = {56 89 45 f0 89 55 f4 ff 15 ?? ?? ?? ?? 0f b7 c0 0f 57 c0 66 89 45 e8 40 66 89 45 ea 8d 45 f8 } //2
		$a_02_2 = {5c 00 62 00 75 00 69 00 6c 00 64 00 65 00 72 00 5f 00 76 00 [0-03] 5c 00 73 00 74 00 65 00 61 00 6c 00 63 00 5c 00 } //5
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2+(#a_02_2  & 1)*5) >=10
 
}