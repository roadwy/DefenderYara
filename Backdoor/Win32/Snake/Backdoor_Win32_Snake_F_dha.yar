
rule Backdoor_Win32_Snake_F_dha{
	meta:
		description = "Backdoor:Win32/Snake.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 04 1f 32 08 6a 01 88 4d ?? 8d 4d ?? 51 50 e8 ?? ?? ?? ?? 83 c4 0c 46 3b 35 ?? ?? ?? ?? 72 02 33 f6 47 3b 7d 0c 72 d2 } //1
		$a_03_1 = {8a 0c 31 03 c7 32 08 6a 01 88 4d ?? 8d 4d ?? 51 50 e8 ?? ?? ?? ?? 83 c4 0c 46 3b f3 72 02 33 f6 47 3b 7d ?? 72 d4 } //1
		$a_01_2 = {73 63 20 25 73 20 63 72 65 61 74 65 20 25 73 20 62 69 6e 50 61 74 68 3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 25 25 53 79 73 74 65 6d 52 6f 6f 74 25 25 5c 25 73 22 3e 3e 25 73 } //1 sc %s create %s binPath= "cmd.exe /c start %%SystemRoot%%\%s">>%s
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}