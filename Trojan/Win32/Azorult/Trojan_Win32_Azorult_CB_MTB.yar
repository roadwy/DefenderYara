
rule Trojan_Win32_Azorult_CB_MTB{
	meta:
		description = "Trojan:Win32/Azorult.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 45 78 8b 4d 7c 31 08 83 c5 70 c9 c2 08 00 8b 44 24 04 8b 4c 24 08 01 08 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_CB_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {59 59 85 c0 75 17 8b 45 fc 8b 4d e8 0f b7 04 41 8b 4d e4 8b 55 08 03 14 81 8b c2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_CB_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_01_0 = {8b 44 24 04 8b 4c 24 08 29 08 c2 08 00 55 8b ec 51 8b 4d 08 8b 45 0c 83 65 fc 00 89 01 8b 45 0c 33 45 fc 89 45 fc 8b 45 fc 89 01 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_CB_MTB_4{
	meta:
		description = "Trojan:Win32/Azorult.CB!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 44 24 14 3d 9d 06 00 00 74 12 40 3d c6 7c 13 01 89 44 24 14 0f 8c c2 fe ff ff eb 0c } //05 00 
		$a_01_1 = {33 c9 33 c0 8d 54 24 20 52 66 89 44 24 14 66 89 4c 24 16 8b 44 24 14 } //00 00 
	condition:
		any of ($a_*)
 
}