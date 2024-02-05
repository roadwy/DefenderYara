
rule Trojan_Win32_Cridex_PVD_MTB{
	meta:
		description = "Trojan:Win32/Cridex.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {03 d6 03 c2 25 ff 00 00 00 8b f0 8a 86 90 01 04 88 81 90 01 04 41 81 f9 00 01 00 00 89 35 90 09 06 00 88 1d 90 00 } //02 00 
		$a_00_1 = {8b 55 e0 03 55 f4 0f b6 02 33 c1 8b 4d e0 03 4d f4 88 01 eb } //02 00 
		$a_00_2 = {8b 45 ec 03 45 fc 0f b6 08 03 4d f4 8b 55 ec 03 55 fc 88 0a } //00 00 
	condition:
		any of ($a_*)
 
}