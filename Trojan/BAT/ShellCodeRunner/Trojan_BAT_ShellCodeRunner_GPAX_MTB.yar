
rule Trojan_BAT_ShellCodeRunner_GPAX_MTB{
	meta:
		description = "Trojan:BAT/ShellCodeRunner.GPAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 72 01 00 00 70 72 05 00 00 70 6f 05 00 00 0a 72 07 00 00 70 72 05 00 00 70 6f 05 00 00 0a 72 0b 00 00 70 72 05 00 00 70 6f 05 00 00 0a 72 0f 00 00 70 72 05 00 00 70 6f 05 00 00 0a 6f 06 00 00 0a } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}