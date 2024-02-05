
rule TrojanDropper_Win32_Boaxxe_D{
	meta:
		description = "TrojanDropper:Win32/Boaxxe.D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {eb 09 8b 4d f8 83 c1 01 89 4d f8 8b 55 f8 3b 55 10 7d 30 8b 45 f4 83 c0 11 6b c0 71 25 ff 00 00 00 89 45 f4 8a 4d f4 88 4d fc 8b 55 08 03 55 f8 0f be 02 0f be 4d fc 33 c1 8b 55 0c 03 55 f8 88 02 eb bf } //01 00 
		$a_01_1 = {eb 09 8b 4d f8 83 c1 01 89 4d f8 8b 55 f8 3b 55 10 7d 41 51 8b 45 f4 b9 11 00 00 00 03 c1 81 c1 48 04 00 00 0f af c1 25 ff ff 01 00 89 45 f4 59 8b 45 f4 25 ff 00 00 00 88 45 fc 8b 4d 08 03 4d f8 0f be 11 0f be 45 fc 33 d0 8b 4d 0c 03 4d f8 88 11 eb ae } //01 00 
		$a_03_2 = {89 85 f0 fd ff ff 83 bd f0 fd ff ff 00 74 16 83 3d 90 01 03 00 00 74 0d 8d 85 f8 fe ff ff 50 ff 15 90 01 03 00 83 7d 90 03 01 01 10 14 02 0f 85 90 01 01 00 00 00 6a 20 8d 8d 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}