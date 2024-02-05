
rule Trojan_BAT_ShellCodeRunner_CXF_MTB{
	meta:
		description = "Trojan:BAT/ShellCodeRunner.CXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 09 11 10 11 08 11 10 9a 1f 10 28 90 01 04 9c 00 11 10 17 58 13 10 11 10 11 08 8e 69 fe 04 13 11 11 11 2d d9 90 00 } //01 00 
		$a_01_1 = {7a 68 77 67 50 48 51 45 78 6c 6f 61 61 44 } //01 00 
		$a_01_2 = {78 71 4d 76 53 6b 75 69 45 } //00 00 
	condition:
		any of ($a_*)
 
}