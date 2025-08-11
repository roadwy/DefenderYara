
rule Trojan_BAT_ShellcodeRunner_EAJ_MTB{
	meta:
		description = "Trojan:BAT/ShellcodeRunner.EAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 17 11 18 11 05 11 18 91 20 aa 00 00 00 61 20 ff 00 00 00 5f d2 9c 11 18 17 58 13 18 11 18 11 05 8e 69 3f d8 ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}