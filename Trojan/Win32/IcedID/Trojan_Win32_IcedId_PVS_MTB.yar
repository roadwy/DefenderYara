
rule Trojan_Win32_IcedId_PVS_MTB{
	meta:
		description = "Trojan:Win32/IcedId.PVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 5c 24 24 69 c5 83 e5 00 00 66 03 c8 8b 02 05 2c 5a 16 01 66 89 0d 90 01 04 8b 3d 90 01 04 2b df 89 02 90 00 } //02 00 
		$a_00_1 = {8a 44 0f 03 8a d0 80 e2 fc c0 e2 04 0a 54 0f 01 88 55 ff 8a d0 24 f0 c0 e0 02 0a 04 0f c0 e2 06 0a 54 0f 02 88 04 1e } //02 00 
		$a_00_2 = {8b 4d fc 8b 55 cc 8b 04 8a 33 05 24 70 44 00 8b 4d fc 8b 55 cc 89 04 8a } //02 00 
		$a_02_3 = {81 c2 f0 a5 f7 01 89 15 90 01 04 89 94 1e e9 fc ff ff 8b 35 90 01 04 ba 04 00 00 00 03 da 81 fb 07 04 00 00 89 15 90 09 06 00 8b 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}