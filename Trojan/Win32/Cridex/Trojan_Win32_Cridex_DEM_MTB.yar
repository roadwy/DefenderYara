
rule Trojan_Win32_Cridex_DEM_MTB{
	meta:
		description = "Trojan:Win32/Cridex.DEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 ea 04 2b 15 90 01 04 89 15 90 01 04 69 05 90 01 04 db 24 00 00 0f b7 4d fc 2b c1 66 89 45 fc 8b 15 90 01 04 81 c2 90 01 04 89 15 90 01 04 a1 90 01 04 03 45 f8 8b 0d 90 01 04 89 88 90 01 04 69 15 90 01 04 db 24 00 00 0f b7 45 fc 2b d0 90 00 } //01 00 
		$a_02_1 = {03 d0 83 fa 26 90 13 b9 01 00 00 00 c1 e1 02 8b 35 90 01 04 83 ee 26 0f b7 45 fc 99 2b f0 0f b6 81 90 01 04 99 03 c6 ba 01 00 00 00 c1 e2 02 88 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}