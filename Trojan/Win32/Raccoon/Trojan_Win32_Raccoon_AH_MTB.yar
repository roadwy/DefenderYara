
rule Trojan_Win32_Raccoon_AH_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {c1 e0 04 89 01 c3 31 08 c3 81 3d 90 01 04 e6 01 90 00 } //0a 00 
		$a_00_1 = {8b 4d fc 03 ca c1 ea 05 89 55 f8 8b 45 e0 01 45 f8 8b 45 ec 51 03 c7 } //00 00 
	condition:
		any of ($a_*)
 
}