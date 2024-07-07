
rule Trojan_Win64_ShellCodeRunner_ASR_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.ASR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 8b c2 0f b7 00 41 8b c8 c1 c9 08 41 ff c1 03 c8 41 8b c1 49 03 c2 44 33 c1 44 38 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}