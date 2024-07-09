
rule Trojan_Win64_ShellcodeRunner_ASDF_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.ASDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 33 e4 48 89 44 24 ?? 44 89 a4 24 c4 00 00 00 49 8b d6 44 8b 45 ?? 48 8b cb 45 8d 4c 24 40 ff 15 ?? ?? ?? 00 48 8b 05 } //2
		$a_03_1 = {4c 8b cd 44 89 64 24 28 45 33 c0 33 d2 48 89 74 24 20 48 8b cb ff 15 ?? ?? ?? 00 48 85 c0 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}