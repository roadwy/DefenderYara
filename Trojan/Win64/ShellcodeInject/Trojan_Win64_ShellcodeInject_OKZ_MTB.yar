
rule Trojan_Win64_ShellcodeInject_OKZ_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeInject.OKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 63 ca 48 b8 f1 f0 f0 f0 f0 f0 f0 f0 45 03 d4 48 f7 e1 48 c1 ea 04 48 6b c2 11 48 2b c8 48 03 cb 8a 44 0c 20 43 32 04 0b 41 88 01 4d 03 cc 41 81 fa 00 7a 3c 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}