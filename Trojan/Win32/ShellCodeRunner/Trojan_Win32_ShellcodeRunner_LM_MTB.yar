
rule Trojan_Win32_ShellcodeRunner_LM_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 e2 07 03 c2 c1 f8 03 89 45 d0 eb ?? 8b 55 d0 83 c2 09 89 55 d0 eb ?? 8b 45 d0 83 e8 08 89 45 d0 } //10
		$a_03_1 = {8b 95 24 ff ff ff 83 ea 04 89 95 24 ff ff ff e9 ?? ?? ?? ?? 6b 85 24 ff ff ff 05 89 85 24 ff ff ff e9 ?? ?? ?? ?? 8b 85 24 ff ff ff 99 b9 05 00 00 00 f7 f9 89 85 24 ff ff ff e9 ?? ?? ?? ?? 8b 95 24 ff ff ff 83 c2 06 89 95 24 ff ff ff } //5
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*5) >=15
 
}