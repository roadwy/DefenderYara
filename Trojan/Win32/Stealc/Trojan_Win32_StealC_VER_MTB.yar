
rule Trojan_Win32_StealC_VER_MTB{
	meta:
		description = "Trojan:Win32/StealC.VER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d7 d3 ea c7 05 90 01 04 ee 3d ea f4 03 55 d8 8b 45 ec 31 45 fc 33 55 fc 89 55 d4 8b 45 d4 83 45 f8 64 29 45 f8 83 6d f8 64 8b 45 f8 90 00 } //01 00 
		$a_03_1 = {8b 45 fc 33 c6 89 45 fc 2b f8 8d 45 e8 e8 90 01 04 83 6d e0 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}