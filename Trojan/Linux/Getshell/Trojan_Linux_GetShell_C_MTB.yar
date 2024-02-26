
rule Trojan_Linux_GetShell_C_MTB{
	meta:
		description = "Trojan:Linux/GetShell.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 45 fc 48 98 48 8d 14 c5 00 00 00 00 48 8b 45 e0 48 01 d0 48 8b 00 48 89 c7 e8 5d fc ff ff 48 89 c2 8b 45 fc 48 98 48 8d 0c c5 00 00 00 00 48 8b 45 e0 48 01 c8 48 8b 00 be 20 00 00 00 48 89 c7 e8 76 fc ff ff 83 45 fc 01 8b 45 fc 3b 45 ec 7c ae } //01 00 
		$a_00_1 = {74 1e 0f 1f 84 00 00 00 00 00 4c 89 ea 4c 89 f6 44 89 ff 41 ff 14 dc 48 83 c3 01 48 39 eb 75 ea 48 83 c4 08 } //01 00 
		$a_00_2 = {e8 12 fd ff ff 85 c0 75 19 be bf 88 00 00 bf cc 0c 40 00 e8 0c fe ff ff bf 00 00 00 00 e8 b5 fc ff ff bf 23 00 00 00 e8 db fc ff ff eb d2 } //00 00 
	condition:
		any of ($a_*)
 
}