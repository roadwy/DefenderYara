
rule Trojan_BAT_Redline_NEL_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {11 05 11 0a 8f 12 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 05 8e 69 32 cd } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Redline_NEL_MTB_2{
	meta:
		description = "Trojan:BAT/Redline.NEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 b6 00 00 06 0b 07 1f 20 8d 90 01 01 00 00 01 25 d0 90 01 01 00 00 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 07 1f 10 8d 90 01 01 00 00 01 25 d0 90 01 01 00 00 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 06 07 6f 90 01 01 00 00 0a 17 73 90 01 01 00 00 0a 0c 08 02 16 02 8e 69 6f 90 01 01 00 00 0a 90 00 } //05 00 
		$a_03_1 = {06 28 81 00 00 0a 8e 69 17 fe 02 0b 28 90 01 01 00 00 06 90 00 } //01 00 
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_3 = {77 00 69 00 66 00 69 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  wifi.Properties.Resources
	condition:
		any of ($a_*)
 
}