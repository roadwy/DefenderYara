
rule Trojan_Win64_ShellCodeRunner_MX_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {12 01 00 4c 8b c7 48 8b d3 8b 08 e8 ?? 9a ff ff 8b d8 e8 61 05 00 00 84 c0 74 55 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}