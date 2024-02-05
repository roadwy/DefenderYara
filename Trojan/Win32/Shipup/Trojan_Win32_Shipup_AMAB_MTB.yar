
rule Trojan_Win32_Shipup_AMAB_MTB{
	meta:
		description = "Trojan:Win32/Shipup.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 e8 01 c2 8b 45 f0 03 45 e0 89 45 ec 8b 45 e8 03 45 ec 41 e8 90 01 04 81 f9 e8 07 00 00 7d 90 01 01 8b 45 e0 89 f3 89 fa e8 90 01 04 89 45 f0 89 f3 89 fa 8b 45 e0 e8 90 01 04 8b 5d e0 85 db 74 90 00 } //01 00 
		$a_01_1 = {89 c6 89 d7 88 d9 0f b6 00 d3 f8 89 c1 0f b6 02 8d 53 01 89 55 fc 99 f7 7d fc 88 06 88 c8 0c 01 0f b6 f0 89 d8 99 f7 fe 0f b6 c9 01 c8 88 07 } //00 00 
	condition:
		any of ($a_*)
 
}