
rule Trojan_Win64_ShellcodeRunner_MZZ_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.MZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 88 04 19 48 ff c1 48 ff ca 48 3b ce 72 ?? 49 8b cd 8d 41 01 30 04 19 48 ff c1 48 3b ce 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}