
rule Trojan_Win32_Farfli_MV_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 73 90 01 01 8b 4d f4 e8 90 01 04 88 45 fb 0f b6 55 fb 8b 45 08 03 45 fc 0f b6 08 33 d1 8b 45 08 03 45 fc 88 10 eb 90 00 } //01 00 
		$a_00_1 = {8a 4c 0e 08 88 4c 02 08 8b 55 f8 8b 42 04 8b 4d f8 8a 55 ff 88 54 01 08 8b 45 f8 8b 48 04 8b 55 f8 0f b6 44 0a 08 8b 4d f8 8b 11 8b 4d f8 0f b6 54 11 08 03 c2 } //00 00 
	condition:
		any of ($a_*)
 
}