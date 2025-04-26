
rule Trojan_Win32_ShellcodeRunner_MEZ_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.MEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 d7 8b 45 fc 33 d2 bb 10 00 00 00 f7 f3 0f b6 92 ?? ?? ?? ?? 23 fa 0b f7 0b ce 8b 45 f8 03 45 fc 88 08 e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}