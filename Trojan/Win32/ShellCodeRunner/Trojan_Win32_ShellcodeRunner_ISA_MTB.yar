
rule Trojan_Win32_ShellcodeRunner_ISA_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.ISA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {57 9c bf b9 b1 35 79 66 81 e7 b9 46 c1 e7 a7 66 f7 df 8b 7c 24 04 c7 44 24 04 06 c8 ef 7f ff 74 24 00 9d 8d 64 24 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}