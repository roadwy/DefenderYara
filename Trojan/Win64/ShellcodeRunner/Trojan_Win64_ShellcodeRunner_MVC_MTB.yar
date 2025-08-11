
rule Trojan_Win64_ShellcodeRunner_MVC_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.MVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8b c0 33 d2 48 8b c3 48 ff c3 48 f7 f6 0f b6 0c 2a 41 30 08 48 8b cf e8 ?? ?? ?? ?? 48 3b d8 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}