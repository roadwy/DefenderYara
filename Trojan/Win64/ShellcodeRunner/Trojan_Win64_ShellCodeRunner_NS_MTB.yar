
rule Trojan_Win64_ShellCodeRunner_NS_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 05 7a 45 45 00 48 89 04 24 48 c7 44 24 08 ?? ?? ?? ?? 48 8b 44 24 30 48 89 44 24 ?? 48 c7 44 24 18 ?? ?? ?? ?? 48 c7 44 24 20 } //3
		$a_03_1 = {45 0f 57 ff 4c 8b 35 d0 5b 4e ?? 65 4d 8b 36 4d 8b 36 48 8b 44 24 ?? 48 8b 6c 24 38 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}