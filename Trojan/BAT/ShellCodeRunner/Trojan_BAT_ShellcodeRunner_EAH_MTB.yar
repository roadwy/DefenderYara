
rule Trojan_BAT_ShellcodeRunner_EAH_MTB{
	meta:
		description = "Trojan:BAT/ShellcodeRunner.EAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 2b 0e 03 06 16 07 6f 06 00 00 0a 08 07 6a 58 0c 02 06 16 06 8e 69 6f 07 00 00 0a 25 0b 16 30 e2 08 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}