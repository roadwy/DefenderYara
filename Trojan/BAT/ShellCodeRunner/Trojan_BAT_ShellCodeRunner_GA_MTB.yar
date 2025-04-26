
rule Trojan_BAT_ShellCodeRunner_GA_MTB{
	meta:
		description = "Trojan:BAT/ShellCodeRunner.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 11 04 06 11 04 91 07 11 04 07 8e 69 5d 91 61 d2 9c 11 04 17 58 13 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}