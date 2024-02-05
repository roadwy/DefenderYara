
rule Trojan_Win32_Grandoreiro_psyW_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.psyW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {74 0f 8b 55 ec 0f af 55 fc 8b 45 fc 2b c2 89 45 fc 8b 4d e4 03 4d f4 8a 55 e0 88 11 8b 45 fc 0f af 45 ec 8b 4d fc 2b c8 89 4d fc ba 84 a7 45 00 83 7d ec 34 75 13 8b 55 fc 33 c9 3b 55 fc 0f 9d c1 8b 45 ec d3 e0 89 45 ec 8b 4d ec 33 4d ec 8b 55 fc d3 e2 89 55 fc e9 ff fe ff ff } //00 00 
	condition:
		any of ($a_*)
 
}