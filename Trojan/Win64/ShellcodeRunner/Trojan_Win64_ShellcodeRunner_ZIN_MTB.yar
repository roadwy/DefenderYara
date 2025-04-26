
rule Trojan_Win64_ShellcodeRunner_ZIN_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.ZIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c0 48 8b 7c 24 50 48 8b 94 24 88 00 00 00 4c 8b 84 24 d0 00 00 00 4c 8b 8c 24 c8 00 00 00 48 39 c5 74 ?? 48 83 f8 10 0f 84 ?? ?? ?? ?? 41 8a 0c 01 41 30 0c 02 48 ff c0 eb e4 49 83 f8 f0 0f 84 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}