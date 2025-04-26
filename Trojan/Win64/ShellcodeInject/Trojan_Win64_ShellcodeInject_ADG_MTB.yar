
rule Trojan_Win64_ShellcodeInject_ADG_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeInject.ADG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 e1 20 83 b8 ed 33 ca 8b d1 d1 e9 41 23 d5 f7 da 81 e2 20 83 b8 ed 33 d1 41 0f b6 09 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}