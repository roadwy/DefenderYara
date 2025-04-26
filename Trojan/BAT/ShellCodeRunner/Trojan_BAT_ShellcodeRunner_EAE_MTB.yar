
rule Trojan_BAT_ShellcodeRunner_EAE_MTB{
	meta:
		description = "Trojan:BAT/ShellcodeRunner.EAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 06 08 6f 26 00 00 0a 6f 27 00 00 0a 6f 23 00 00 0a 26 08 17 58 0c 08 03 32 e5 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}