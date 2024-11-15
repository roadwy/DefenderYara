
rule Trojan_Win32_ShellcodeRunner_HNC_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.HNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 c2 42 30 01 3b d6 } //2
		$a_03_1 = {2a d0 80 c2 ?? 30 54 0d ?? 41 83 f9 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}