
rule Trojan_Win32_IcedID_PVK_MTB{
	meta:
		description = "Trojan:Win32/IcedID.PVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 54 24 10 05 9c 29 cd 01 a3 90 01 04 89 02 90 09 05 00 a1 90 00 } //02 00 
		$a_02_1 = {8b d7 b8 7c 00 00 00 03 c2 83 e8 7c a3 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //02 00 
		$a_00_2 = {8b 4d 0c 8b 45 fc 33 d2 03 c8 f7 75 14 8b 45 08 8a 04 50 30 01 } //02 00 
		$a_00_3 = {8a 04 0e 8b 4c 24 60 81 c1 66 d4 e1 0e 30 f8 89 4c 24 60 8b 4c 24 44 88 04 11 } //00 00 
	condition:
		any of ($a_*)
 
}