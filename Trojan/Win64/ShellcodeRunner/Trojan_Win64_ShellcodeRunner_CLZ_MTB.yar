
rule Trojan_Win64_ShellcodeRunner_CLZ_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.CLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 4d 63 c2 4d 3b c1 48 8d 49 ?? 48 0f 45 d0 0f b6 04 1a 30 41 ff 33 c0 4d 3b c1 41 0f 45 c2 44 8d 50 01 48 8d 42 01 49 83 eb 01 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}