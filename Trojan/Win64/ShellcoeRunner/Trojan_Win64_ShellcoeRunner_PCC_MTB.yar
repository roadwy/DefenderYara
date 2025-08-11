
rule Trojan_Win64_ShellcoeRunner_PCC_MTB{
	meta:
		description = "Trojan:Win64/ShellcoeRunner.PCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 0f b6 44 05 a0 8b 95 ?? 07 00 00 48 63 ca 48 8b 95 ?? 07 00 00 48 01 ca 32 85 ?? 07 00 00 88 02 83 85 ?? 07 00 00 01 8b 85 ?? 07 00 00 3d 1f 08 00 00 76 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}