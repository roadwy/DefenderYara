
rule Trojan_Win64_ShellcodeRunner_GPD_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.GPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {48 8b 74 24 40 48 8d 56 f0 48 89 54 24 40 48 f7 da 48 c1 fa 3f 83 e2 10 48 8b 4c 24 48 48 01 ca 48 89 54 24 48 90 48 8b 5c 24 50 41 b8 01 00 00 00 48 8b 44 24 60 } //00 00 
	condition:
		any of ($a_*)
 
}