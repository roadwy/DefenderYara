
rule Trojan_Win32_ShellcodeRunner_AGZ_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.AGZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e9 03 d1 c1 fa 05 8b c2 c1 e8 1f 03 c2 8a d0 c0 e2 03 2a d0 8a c1 c0 e2 03 2a c2 04 39 30 44 0d ?? 41 83 f9 1d 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}