
rule Trojan_Win64_ShellCodeRunner_NS_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 05 7a 45 45 00 48 89 04 24 48 c7 44 24 08 ?? ?? ?? ?? 48 8b 44 24 30 48 89 44 24 ?? 48 c7 44 24 18 ?? ?? ?? ?? 48 c7 44 24 20 } //3
		$a_03_1 = {45 0f 57 ff 4c 8b 35 d0 5b 4e ?? 65 4d 8b 36 4d 8b 36 48 8b 44 24 ?? 48 8b 6c 24 38 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}
rule Trojan_Win64_ShellCodeRunner_NS_MTB_2{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {40 32 f6 40 88 74 24 ?? e8 fe 03 00 00 8a d8 8b 0d 96 1a 02 00 83 f9 01 0f 84 23 01 00 00 85 c9 75 4a c7 05 7f 1a 02 00 ?? ?? ?? ?? 48 8d 15 e8 59 01 00 48 8d 0d a9 59 01 00 } //2
		$a_03_1 = {48 8d 05 d2 13 02 00 89 74 24 68 48 89 45 80 48 8d 05 b3 13 02 00 48 89 45 88 c7 44 24 78 ?? ?? ?? ?? e8 a2 f9 ff ff } //3
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}