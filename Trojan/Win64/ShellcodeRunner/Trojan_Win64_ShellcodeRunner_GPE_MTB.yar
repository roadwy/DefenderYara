
rule Trojan_Win64_ShellcodeRunner_GPE_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.GPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 89 ca 49 f7 d9 49 c1 f9 3f 41 83 e1 10 48 8b 74 24 48 4c 01 ce 48 8b 78 18 48 89 d8 48 8b 5c 24 58 48 8b 4c 24 38 49 89 c8 49 89 d1 48 89 fa 48 89 cf } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}