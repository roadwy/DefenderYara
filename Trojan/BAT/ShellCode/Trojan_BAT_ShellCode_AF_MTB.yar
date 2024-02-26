
rule Trojan_BAT_ShellCode_AF_MTB{
	meta:
		description = "Trojan:BAT/ShellCode.AF!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {02 06 91 03 06 91 fe 01 0c 08 2d 05 00 16 0b 2b 13 00 06 17 58 0a 06 02 8e 69 fe 04 0c 08 2d df } //0a 00 
		$a_01_1 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d e1 } //00 00 
	condition:
		any of ($a_*)
 
}