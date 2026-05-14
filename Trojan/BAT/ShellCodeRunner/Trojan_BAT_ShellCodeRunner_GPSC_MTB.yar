
rule Trojan_BAT_ShellCodeRunner_GPSC_MTB{
	meta:
		description = "Trojan:BAT/ShellCodeRunner.GPSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 1f 47 8c 11 00 00 01 a2 11 1d 17 1f 65 8c 11 00 00 01 a2 11 1d 18 1f 6e 8c 11 00 00 01 a2 11 1d 19 1f 65 8c 11 00 00 01 a2 11 1d 1a 1f 72 8c 11 00 00 01 a2 11 1d 1b 1f 61 } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}