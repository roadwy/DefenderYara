
rule Backdoor_Win32_Simda_BA_MTB{
	meta:
		description = "Backdoor:Win32/Simda.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 4d e0 33 d2 8a 91 90 02 04 8b 45 e0 25 90 02 04 83 c0 90 01 01 33 d0 8b 4d ec 03 4d e0 88 11 eb cc 90 00 } //02 00 
		$a_01_1 = {33 d2 f7 36 33 ca 8b 55 08 89 0a eb d0 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}