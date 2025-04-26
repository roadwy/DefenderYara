
rule Trojan_Win32_ShellcodeRunner_CCIR_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.CCIR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e8 3f c6 45 e9 6f c6 45 ea 2b c6 45 eb d3 c6 45 ec 20 c6 45 ed b2 c6 45 ee c1 c6 45 ef 77 c6 45 f0 42 c6 45 f1 4c c6 45 f2 63 c6 45 f3 6d c6 45 f4 09 c6 45 f5 8a c6 45 f6 ec c6 45 f7 ed c6 45 f8 a3 c6 45 f9 29 c6 45 fa 36 } //2
		$a_01_1 = {51 50 53 57 53 ff 75 0c ff 15 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}