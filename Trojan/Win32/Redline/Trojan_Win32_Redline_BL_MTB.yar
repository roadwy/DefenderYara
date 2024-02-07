
rule Trojan_Win32_Redline_BL_MTB{
	meta:
		description = "Trojan:Win32/Redline.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {3b cf 73 0e 8b c1 83 e0 03 8a 80 90 02 04 30 04 0e 41 3b ca 72 e9 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_03_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 90 02 20 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}