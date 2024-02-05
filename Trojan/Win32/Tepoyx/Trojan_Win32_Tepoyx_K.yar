
rule Trojan_Win32_Tepoyx_K{
	meta:
		description = "Trojan:Win32/Tepoyx.K,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 0c 46 32 cb 81 e1 ff 00 00 00 66 89 0c 46 40 4a 75 ed } //01 00 
		$a_01_1 = {68 72 06 00 00 6a 10 6a 25 6a 4f 6a 6e 6a 6f 8b cf 8b d3 8b c6 e8 } //01 00 
		$a_00_2 = {26 00 69 00 6c 00 76 00 6c 00 3d 00 } //00 00 
	condition:
		any of ($a_*)
 
}