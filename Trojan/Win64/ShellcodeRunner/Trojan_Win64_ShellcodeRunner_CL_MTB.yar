
rule Trojan_Win64_ShellcodeRunner_CL_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 00 31 c6 89 f1 48 8b 15 90 01 03 00 8b 45 fc 48 98 48 01 d0 90 00 } //02 00 
		$a_03_1 = {31 c1 48 8b 55 90 01 01 8b 45 90 01 01 48 98 88 0c 02 83 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}