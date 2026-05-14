
rule Trojan_Win64_ShellcodeRunner_NSG_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NSG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 b8 60 17 74 50 71 78 53 ac ?? ?? ?? ?? ?? ?? ?? 48 b8 58 22 60 3f 98 c8 78 35 } //2
		$a_01_1 = {48 b8 e9 53 14 6a 34 70 a0 c0 ?? ?? ?? ?? ?? ?? ?? 48 b8 b0 fc e9 1c c3 c6 57 c6 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}