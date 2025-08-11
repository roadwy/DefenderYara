
rule Trojan_Win64_ShellcodeRunner_PCP_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.PCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 85 fc 0f 00 00 0f b6 44 05 a0 32 85 0f 10 00 00 89 c2 48 8b 85 00 10 00 00 88 10 8b 85 ?? ?? ?? ?? d1 e8 00 85 0f 10 00 00 48 83 85 00 10 00 00 01 83 85 fc 0f 00 00 02 8b 85 fc 0f 00 00 3b 85 ec 0f 00 00 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}