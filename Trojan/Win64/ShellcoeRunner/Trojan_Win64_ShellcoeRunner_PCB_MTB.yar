
rule Trojan_Win64_ShellcoeRunner_PCB_MTB{
	meta:
		description = "Trojan:Win64/ShellcoeRunner.PCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 01 d0 89 ca 88 10 48 8b 95 ?? 07 00 00 48 8b 85 ?? 07 00 00 48 01 d0 0f b6 00 48 8b 8d ?? 07 00 00 48 8b 95 ?? 07 00 00 48 01 ca 32 85 ?? 07 00 00 88 02 48 83 85 ?? 07 00 00 01 48 8b 85 ?? 07 00 00 48 3b 85 ?? 07 00 00 0f 82 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}