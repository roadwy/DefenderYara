
rule Trojan_BAT_ShellCodeRunner_GPSA_MTB{
	meta:
		description = "Trojan:BAT/ShellCodeRunner.GPSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 26 5d 28 ?? 00 00 0a 25 26 0c 08 61 0d 06 09 d1 6f ?? 00 00 0a 25 26 26 07 18 58 0b 07 02 } //8
	condition:
		((#a_03_0  & 1)*8) >=8
 
}