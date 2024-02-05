
rule Trojan_Win32_Redline_FE_MTB{
	meta:
		description = "Trojan:Win32/Redline.FE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 49 00 8a 8c 02 3b 2d 0b 00 88 0c 30 40 3b 05 a4 1b 4c 02 } //01 00 
		$a_01_1 = {8b 44 24 38 01 44 24 10 33 74 24 18 31 74 24 10 } //01 00 
		$a_01_2 = {8a 8c 02 3b 2d 0b 00 88 0c 30 40 3b 05 34 22 4c 02 } //00 00 
	condition:
		any of ($a_*)
 
}