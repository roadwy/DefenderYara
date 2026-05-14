
rule Trojan_Win64_ShellcodeRunner_AHA_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.AHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 98 8b 8c 24 ?? ?? 00 00 89 8c 84 ?? ?? 00 00 8b 84 24 ?? 12 00 00 ff c0 48 98 8b 8c 24 } //20
		$a_03_1 = {83 f8 10 7d ?? 8b 84 24 ?? ?? 00 00 ?? c0 [0-07] 8b 8c 24 ?? ?? 00 00 03 c1 35 ?? ?? ?? ?? 8b 8c 24 ?? ?? 00 00 48 63 c9 48 6b c9 40 48 8d 8c 0c ?? ?? 00 00 8b 94 24 ?? ?? 00 00 48 63 d2 89 04 91 eb } //30
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}