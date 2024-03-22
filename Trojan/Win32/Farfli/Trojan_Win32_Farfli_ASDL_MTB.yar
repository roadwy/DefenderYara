
rule Trojan_Win32_Farfli_ASDL_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {68 78 da 04 00 6a 00 ff 15 90 01 03 00 50 ff 15 90 00 } //01 00 
		$a_01_1 = {33 c0 56 8b f1 57 b9 9e 36 01 00 8d 7e 10 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00  WaitForSingleObject
	condition:
		any of ($a_*)
 
}