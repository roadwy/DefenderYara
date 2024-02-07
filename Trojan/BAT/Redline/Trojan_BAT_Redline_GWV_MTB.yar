
rule Trojan_BAT_Redline_GWV_MTB{
	meta:
		description = "Trojan:BAT/Redline.GWV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {07 06 08 06 8e 69 5d 91 02 08 91 61 d2 6f 90 01 03 0a 08 17 58 0c 08 02 8e 69 32 e4 07 2a 90 00 } //01 00 
		$a_01_1 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Redline_GWV_MTB_2{
	meta:
		description = "Trojan:BAT/Redline.GWV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {02 06 58 0b 07 06 25 1f 3b 5c 1f 3b 5a 59 1f 38 58 08 07 58 46 61 52 06 17 58 0a 06 1f 13 37 e0 } //01 00 
		$a_01_1 = {50 72 6f 6a 65 63 74 33 35 } //01 00  Project35
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_3 = {53 65 63 75 72 65 53 74 72 69 6e 67 3c 31 33 2c 35 36 2c 35 38 2c 63 68 61 72 3e } //01 00  SecureString<13,56,58,char>
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  WriteProcessMemory
	condition:
		any of ($a_*)
 
}