
rule Trojan_Win32_Vidar_PR_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 4c 24 20 8b f0 c1 ee 05 03 74 24 2c 03 c5 33 f1 33 f0 2b fe } //01 00 
		$a_01_1 = {33 f3 31 74 24 14 8b 44 24 14 29 44 24 18 } //00 00 
	condition:
		any of ($a_*)
 
}