
rule Trojan_Win64_ShellcodeInject_HM_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeInject.HM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 5d e8 48 c1 e3 0d 48 31 5d e8 48 8b 75 e8 48 c1 ee 07 48 31 75 e8 48 8b 4d e8 48 c1 e1 11 48 31 4d e8 8b 55 e8 89 55 f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}