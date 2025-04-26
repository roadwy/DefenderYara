
rule Trojan_BAT_ShellcodeRunner_EAG_MTB{
	meta:
		description = "Trojan:BAT/ShellcodeRunner.EAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 6f 10 00 00 0a 0d 7e 01 00 00 04 12 03 28 11 00 00 0a 6f 12 00 00 0a 2c 1a 06 7e 01 00 00 04 12 03 28 11 00 00 0a 6f 13 00 00 0a 28 14 00 00 0a 0a 2b 0e 06 12 03 28 11 00 00 0a 28 14 00 00 0a 0a 08 17 58 0c 08 07 6f 15 00 00 0a 32 b0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}