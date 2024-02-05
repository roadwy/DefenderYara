
rule Trojan_Win32_Winzlock_A{
	meta:
		description = "Trojan:Win32/Winzlock.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 85 34 ff ff ff 8b 48 04 8b 55 f0 89 51 08 8b 45 f0 89 45 ec 8b 4d ec 8b 51 04 } //01 00 
		$a_03_1 = {83 c4 08 8b 4d 08 03 4d f8 88 01 8b 55 f8 3b 55 0c 73 90 01 01 8b 45 f8 83 c0 01 89 45 f8 eb 90 00 } //01 00 
		$a_01_2 = {83 ec 3c 8b 45 0c 03 45 08 2b 45 0c 89 45 fc 8d 4d fc 51 b9 } //01 00 
		$a_01_3 = {89 45 fc 8b 4d fc 89 8d d4 fd ff ff 8d 95 18 fd ff ff 89 55 f8 b8 01 00 00 00 85 c0 } //00 00 
	condition:
		any of ($a_*)
 
}