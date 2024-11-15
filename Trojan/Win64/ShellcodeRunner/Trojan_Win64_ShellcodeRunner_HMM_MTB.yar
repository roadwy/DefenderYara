
rule Trojan_Win64_ShellcodeRunner_HMM_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.HMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 08 80 f1 03 88 08 44 0f b6 c1 f6 c2 01 75 07 41 80 f0 02 44 88 00 ff c2 48 ff c0 3b d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}