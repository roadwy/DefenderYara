
rule Trojan_Win64_ShellcodeRunner_AMMA_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.AMMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 31 c6 89 f1 48 8b 15 90 01 04 8b 45 fc 48 98 48 01 d0 89 ca 88 10 83 45 fc 01 8b 45 fc 48 63 d0 48 8b 05 90 01 04 48 39 c2 72 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}