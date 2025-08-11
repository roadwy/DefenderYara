
rule Trojan_BAT_ShellcodeRunner_NP_MTB{
	meta:
		description = "Trojan:BAT/ShellcodeRunner.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 09 16 1a 6f ?? 00 00 0a 1a fe 01 13 0a 11 0a 2d 08 16 13 09 dd ?? 00 00 00 09 16 28 ?? 00 00 0a 13 07 08 11 07 11 06 d2 6f ?? 00 00 0a 00 00 11 06 17 58 13 06 11 06 20 00 01 00 00 fe 04 13 0a 11 0a 2d ba } //2
		$a_03_1 = {13 07 11 05 11 08 08 11 07 6f ?? 00 00 0a 20 00 01 00 00 58 11 08 20 00 01 00 00 5d 59 20 00 01 00 00 5d d2 28 ?? 00 00 0a 00 11 08 17 58 13 08 00 07 09 16 1a 6f ?? 00 00 0a 1a fe 01 13 0a 11 0a } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}