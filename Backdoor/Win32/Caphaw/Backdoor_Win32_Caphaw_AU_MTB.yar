
rule Backdoor_Win32_Caphaw_AU_MTB{
	meta:
		description = "Backdoor:Win32/Caphaw.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 54 0d f8 03 55 b8 a1 90 02 04 03 45 c8 8a 08 02 ca 8b 15 90 02 04 03 55 c8 88 0a 8b 85 90 02 04 83 c0 01 89 85 90 02 04 81 7d 90 02 05 75 09 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}