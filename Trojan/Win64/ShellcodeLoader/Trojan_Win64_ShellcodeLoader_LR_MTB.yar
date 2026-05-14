
rule Trojan_Win64_ShellcodeLoader_LR_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeLoader.LR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {34 15 41 88 03 49 ff c3 41 8a 03 84 c0 } //20
		$a_01_1 = {48 83 ec 50 48 8d 45 20 c7 45 20 75 00 72 00 48 89 45 d8 48 8d 55 d8 48 8d 45 28 c7 45 24 6c 00 00 00 48 89 45 e0 41 b8 04 00 00 00 48 8d 45 18 c7 45 28 6d 00 6f 00 48 89 45 e8 48 8d 45 d0 48 89 45 f0 c7 45 2c 6e 00 00 00 c7 45 18 2e 00 00 00 c7 45 d0 64 00 6c 00 c7 45 d4 6c 00 00 00 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}