
rule Trojan_Win32_Injuke_CF_MTB{
	meta:
		description = "Trojan:Win32/Injuke.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 04 0b 0f b6 c8 8b 02 d3 c8 8b 4c 24 14 33 c7 2b c3 89 02 83 c2 04 4b 75 e6 } //01 00 
		$a_01_1 = {30 02 42 4e 75 fa } //02 00 
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}