
rule Trojan_Win64_ShellInject_DC_MTB{
	meta:
		description = "Trojan:Win64/ShellInject.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8b 4d f8 48 8d 4d e0 4c 8b 45 e0 45 33 e4 49 83 f9 0f 48 8b c3 49 0f 47 c8 33 d2 49 f7 f6 8a 04 0a 42 30 04 3b 49 83 f9 0f 76 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}