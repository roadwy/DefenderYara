
rule Trojan_Win64_ShellcodeInject_MKB_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeInject.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 0d ea 1a 10 00 48 89 4c 24 68 48 c7 44 24 70 02 00 00 00 48 c7 84 24 88 00 00 00 00 00 00 00 48 8d 4c 24 48 48 89 4c 24 78 48 c7 84 24 80 00 00 00 02 00 00 00 48 8d 4c 24 68 48 89 c2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}