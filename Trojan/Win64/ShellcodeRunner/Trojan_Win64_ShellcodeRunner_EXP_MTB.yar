
rule Trojan_Win64_ShellcodeRunner_EXP_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.EXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 45 e4 20 48 8b 05 43 a0 04 00 48 89 05 0c a0 04 00 eb 65 } //1
		$a_01_1 = {8b 05 8e a0 04 00 48 8b 0d bb a0 04 00 31 04 31 48 83 c6 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}