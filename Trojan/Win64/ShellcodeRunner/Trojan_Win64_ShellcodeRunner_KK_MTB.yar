
rule Trojan_Win64_ShellcodeRunner_KK_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {4e 8d 1c 11 49 8b 03 4d 8b 4b 08 49 33 00 4d 33 48 08 4c 09 c8 } //20
		$a_03_1 = {0f b6 01 0f af c2 88 01 [0-0f] 48 83 c1 01 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}
rule Trojan_Win64_ShellcodeRunner_KK_MTB_2{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 85 70 20 00 00 48 8d 50 01 48 89 95 70 20 00 00 8b 95 7c 20 00 00 8d 4a 01 89 8d 7c 20 00 00 0f b6 08 48 63 c2 88 4c 05 d0 } //20
		$a_01_1 = {8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 0f b6 00 8d 48 fb 8b 45 fc 48 63 d0 48 8b 45 f0 48 01 d0 89 ca 88 10 83 45 fc 01 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_Win64_ShellcodeRunner_KK_MTB_3{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {d1 e8 89 c2 8b 45 ?? 83 e0 01 f7 d8 25 78 3b f6 82 31 d0 89 45 ?? 83 45 ?? 01 } //20
		$a_03_1 = {48 b8 6b 65 72 6e 65 6c 33 32 48 89 45 ?? 48 b8 6c 33 32 2e 64 6c 6c 00 48 89 45 ?? 48 b8 4b 45 52 4e 45 4c 33 32 48 89 45 ?? 48 b8 4c 33 32 2e 44 4c 4c 00 48 89 45 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}