
rule Trojan_Win64_ShellcoeRunner_PCA_MTB{
	meta:
		description = "Trojan:Win64/ShellcoeRunner.PCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 85 f4 07 00 00 0f b6 84 05 b0 03 00 00 32 85 f3 07 00 00 89 c2 48 8b 85 f8 07 00 00 88 10 48 83 85 ?? 07 00 00 01 83 85 ?? 07 00 00 01 8b 85 ?? 07 00 00 3b 85 dc 07 00 00 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}