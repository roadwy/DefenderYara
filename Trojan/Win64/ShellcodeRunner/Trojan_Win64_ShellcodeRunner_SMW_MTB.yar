
rule Trojan_Win64_ShellcodeRunner_SMW_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.SMW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b c2 88 44 24 4e 0f b6 44 24 4e 0f b6 84 04 20 01 00 00 88 44 24 4f 8b 44 24 54 0f b6 4c 24 4f 48 8b 94 24 88 00 00 00 0f b6 04 02 33 c1 8b 4c 24 54 48 8b 94 24 88 00 00 00 88 04 0a } //2
		$a_01_1 = {48 33 c0 4d 33 d2 49 83 c2 60 65 49 8b 02 48 8b 40 18 48 8b 40 10 48 8b 00 48 8b 00 48 8b 40 30 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}