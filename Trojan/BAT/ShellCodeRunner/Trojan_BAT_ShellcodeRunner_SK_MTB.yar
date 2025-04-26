
rule Trojan_BAT_ShellcodeRunner_SK_MTB{
	meta:
		description = "Trojan:BAT/ShellcodeRunner.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 06 9a 13 07 00 7e 01 00 00 04 11 04 11 07 72 96 12 00 70 72 9a 12 00 70 6f 13 00 00 0a 1f 10 28 14 00 00 0a 9c 11 04 17 58 13 04 00 11 06 17 58 13 06 11 06 11 05 8e 69 32 c3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}