
rule Trojan_BAT_ShellcodeRunner_EACL_MTB{
	meta:
		description = "Trojan:BAT/ShellcodeRunner.EACL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 72 01 00 00 70 02 08 18 5a 18 6f 08 00 00 0a 28 09 00 00 0a 0d 09 1f 10 28 0a 00 00 0a 13 04 06 08 11 04 d2 9c 00 08 17 58 0c 08 07 fe 04 13 07 11 07 2d cb } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}