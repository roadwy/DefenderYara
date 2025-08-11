
rule Trojan_BAT_ShellcodeRunner_EDJ_MTB{
	meta:
		description = "Trojan:BAT/ShellcodeRunner.EDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 8f 09 00 00 01 25 71 09 00 00 01 72 49 00 00 70 08 20 80 00 00 00 5d 6f 06 00 00 0a d2 61 d2 81 09 00 00 01 08 17 58 0c 08 07 17 59 33 d0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}