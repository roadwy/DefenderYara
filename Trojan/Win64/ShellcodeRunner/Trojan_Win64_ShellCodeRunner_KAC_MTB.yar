
rule Trojan_Win64_ShellCodeRunner_KAC_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8d 55 a0 48 8b 85 ?? ?? 00 00 48 01 d0 0f b6 00 48 8b 8d ?? ?? 00 00 48 8b 95 ?? ?? 00 00 48 01 ca 32 85 ?? ?? 00 00 88 02 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}