
rule Trojan_Win64_ShellcodeRunner_MAZ_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.MAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 41 0f b6 c0 41 c0 e0 02 48 f7 f1 41 02 d0 02 d1 30 14 19 48 ff c1 48 3b cf 0f 82 7a ff ff ff } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}