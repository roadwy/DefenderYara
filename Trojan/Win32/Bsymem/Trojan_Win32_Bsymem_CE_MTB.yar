
rule Trojan_Win32_Bsymem_CE_MTB{
	meta:
		description = "Trojan:Win32/Bsymem.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 12 40 3d 89 36 13 01 89 44 24 18 0f 8c } //01 00 
		$a_03_1 = {46 81 fe 93 22 0b 18 89 1d 90 02 04 7c c3 90 00 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}