
rule Trojan_Win32_SystemBC_psyJ_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.psyJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 8b 08 83 c1 01 8b 55 fc 89 0a 8b 45 fc 8b 88 8c 02 00 00 83 c1 01 8b 55 fc 89 8a 8c 02 00 00 8b 45 fc 83 38 04 73 5c 8b 45 fc 8b 4d fc 8b 90 8c 02 00 00 3b 51 08 73 4b 8b 45 fc 8b 88 90 02 00 00 8b 55 fc 8b 82 8c 02 00 00 0f b6 0c 01 8b 55 fc 8b 02 8b 55 fc 0f b6 44 02 4c 33 c8 8b 55 fc 8b 42 20 8b 55 fc 8b 92 8c 02 00 00 88 0c 10 8b 45 fc 83 b8 8c 02 00 00 02 75 03 ff 75 fc e9 7a ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}