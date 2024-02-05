
rule Trojan_Win32_Kryptik_GM_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 3b 05 90 01 04 72 90 01 01 eb 90 01 01 8b 4d fc 89 4d f4 8b 15 90 01 04 03 55 fc 89 15 90 01 04 8b 45 f4 50 68 90 01 04 e8 90 01 04 83 c4 90 01 01 8b 4d f0 8b 55 fc 8d 84 0a 90 01 04 89 45 ec 8b 0d 90 01 04 89 0d 90 01 04 8b 55 fc 83 c2 90 01 01 89 55 fc 8b 45 ec a3 90 01 04 e8 90 01 04 b9 90 01 04 85 c9 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}