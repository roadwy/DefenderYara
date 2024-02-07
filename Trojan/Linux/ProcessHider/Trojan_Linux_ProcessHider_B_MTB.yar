
rule Trojan_Linux_ProcessHider_B_MTB{
	meta:
		description = "Trojan:Linux/ProcessHider.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {55 48 89 e5 48 81 ec 20 02 00 00 48 89 bd e8 fd ff ff 48 8b 05 13 2d 00 00 48 85 c0 75 4c 48 8d 35 ac 0c 00 00 48 c7 c7 ff ff ff ff e8 43 fd ff ff 48 89 05 f4 2c 00 00 48 8b 05 ed 2c 00 00 48 85 c0 75 26 e8 3b fd ff ff 48 89 c2 48 8b 05 39 2c 00 00 48 8b 00 48 8d 35 7e 0c 00 00 48 89 c7 b8 00 00 00 00 e8 da fc ff ff 48 8b 15 bb 2c 00 00 48 8b 85 e8 fd ff ff 48 89 c7 ff d2 48 89 45 f8 48 83 7d f8 00 74 7c 48 8d 8d f0 fd ff ff 48 8b 85 e8 fd ff ff ba 00 01 00 00 48 89 ce 48 89 c7 e8 b3 fd ff ff 85 c0 74 5a 48 8d 85 f0 fd ff ff 48 8d 35 37 0c 00 00 48 89 c7 e8 64 fc ff ff 85 c0 75 40 48 8b 45 f8 48 8d 50 13 48 8d 85 f0 fe ff ff 48 89 c6 48 89 d7 e8 0b fe ff ff 85 c0 74 22 48 8b 15 33 2c 00 00 48 8d 85 f0 fe ff ff 48 89 d6 48 89 c7 e8 29 fc ff ff 85 c0 75 05 } //01 00 
		$a_00_1 = {8b 55 fc 48 8d 45 b0 89 d1 48 8d 15 01 0e 00 00 be 40 00 00 00 48 89 c7 b8 00 00 00 00 e8 49 fe ff ff 48 8b 55 98 48 8b 4d a0 48 8d 45 b0 48 89 ce 48 89 c7 e8 02 fe ff ff 48 89 45 f0 48 83 7d f0 ff 75 07 b8 00 00 00 00 eb 13 48 8b 55 f0 } //01 00 
		$a_00_2 = {78 6d 72 69 67 } //00 00  xmrig
	condition:
		any of ($a_*)
 
}