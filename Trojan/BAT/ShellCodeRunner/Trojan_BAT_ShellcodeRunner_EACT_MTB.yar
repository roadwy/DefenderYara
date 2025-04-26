
rule Trojan_BAT_ShellcodeRunner_EACT_MTB{
	meta:
		description = "Trojan:BAT/ShellcodeRunner.EACT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 07 08 02 08 18 5a 18 6f 10 00 00 0a 1f 10 28 11 00 00 0a 9c 00 08 17 58 0c 08 06 fe 04 0d 09 2d de } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}