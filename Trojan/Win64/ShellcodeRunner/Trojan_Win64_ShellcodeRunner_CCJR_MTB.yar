
rule Trojan_Win64_ShellcodeRunner_CCJR_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.CCJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4d e0 48 8d 45 c0 48 89 44 24 28 45 33 c9 45 33 c0 48 89 5c 24 20 33 d2 ff 15 } //2
		$a_01_1 = {4c 8d 4d d0 ba 20 f2 08 00 41 b8 40 00 00 00 48 8b cb ff 15 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}