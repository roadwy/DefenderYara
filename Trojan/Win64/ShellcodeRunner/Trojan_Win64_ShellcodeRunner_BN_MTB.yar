
rule Trojan_Win64_ShellcodeRunner_BN_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {44 29 c2 44 6b c2 90 01 01 44 29 c0 89 c2 89 d0 83 c0 90 01 01 31 c1 48 8b 55 e0 8b 45 d4 48 98 88 0c 02 83 45 d4 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}