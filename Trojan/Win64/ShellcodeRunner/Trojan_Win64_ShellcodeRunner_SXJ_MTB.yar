
rule Trojan_Win64_ShellcodeRunner_SXJ_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.SXJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 89 f0 49 f7 e5 48 d1 ea 8d 04 52 44 89 f2 29 c2 4c 89 f9 e8 ?? ?? ?? ?? 0f b6 00 42 30 04 33 49 ff c6 4c 39 f6 75 } //20
		$a_03_1 = {4c 31 ca 49 0f af d4 0f b6 f7 48 31 d6 49 0f af f4 44 0f b6 f0 49 31 f6 4d 0f af f4 49 31 ce 4d 0f af f4 48 8b 85 ?? ?? ?? ?? 4c 21 f0 48 8d 34 00 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}