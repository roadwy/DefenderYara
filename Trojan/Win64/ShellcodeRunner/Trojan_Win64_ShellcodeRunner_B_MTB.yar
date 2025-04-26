
rule Trojan_Win64_ShellcodeRunner_B_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 48 8b 45 f0 41 b8 23 00 00 00 48 89 c1 e8 ?? ?? ff ff 48 89 45 e8 e8 ?? ?? 00 00 48 98 48 89 45 e0 48 8b 45 e0 48 89 c2 48 83 ea 01 48 89 55 d8 48 83 c0 0f 48 c1 e8 04 48 c1 e0 04 e8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}