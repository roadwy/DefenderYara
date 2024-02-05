
rule Trojan_Win32_Citadel_MA_MTB{
	meta:
		description = "Trojan:Win32/Citadel.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {13 1d d1 b7 40 00 8b 4d ec 33 ce 21 1d f9 b7 40 00 41 81 35 89 b7 40 00 15 b8 40 00 33 ce 89 4d ec 40 8b 0d a0 b1 40 00 89 3d 15 b8 40 00 8b 89 94 01 00 00 bb dd 67 00 00 8b 19 8b cb 8b 5b 3c 3b 44 0b 28 c7 05 7d b7 40 00 41 48 00 00 0f 82 } //00 00 
	condition:
		any of ($a_*)
 
}