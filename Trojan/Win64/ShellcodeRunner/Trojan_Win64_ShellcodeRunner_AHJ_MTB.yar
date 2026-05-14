
rule Trojan_Win64_ShellcodeRunner_AHJ_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.AHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 73 76 61 67 65 6e 74 5f [0-0a] 5f 78 6f 72 } //20
		$a_03_1 = {8d 04 19 49 8b [0-08] f7 e1 ?? ?? ?? 48 ?? ?? ?? 48 [0-06] 48 ?? ?? 48 2b ?? 0f b6 44 ?? 30 43 32 04 ?? 41 88 00 } //30
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}