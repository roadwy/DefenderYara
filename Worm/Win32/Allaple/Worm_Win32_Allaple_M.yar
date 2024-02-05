
rule Worm_Win32_Allaple_M{
	meta:
		description = "Worm:Win32/Allaple.M,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 c4 e8 e8 00 00 00 00 5e 81 e6 00 00 ff ff 6a 30 59 64 8b 01 8b 40 0c 8b 40 1c 8b 00 8b 78 08 57 68 8e 4e 0e ec e8 52 02 00 00 89 45 f4 57 68 aa fc 0d 7c e8 44 02 00 00 89 45 f0 57 68 54 ca af 91 e8 36 02 00 00 89 45 ec 57 68 ac 33 06 03 e8 28 02 00 00 89 45 e8 6a 40 68 00 10 00 00 68 00 00 02 00 6a 00 ff 55 ec 89 45 fc 8b fe 03 76 3c 0f b7 4e 06 81 c6 f8 00 00 00 eb 10 8d 16 81 3a 2e 64 61 74 75 02 eb 08 83 c6 28 49 0b c9 75 ec 8b 46 0c 03 c7 ff 75 fc 50 e8 4e 02 00 00 8b 7d fc 03 7f 3c 6a 40 68 00 10 00 00 ff 77 50 6a 00 ff 55 ec 89 45 f8 ff 75 f8 ff 75 fc e8 ab 00 00 00 ff 75 f0 ff 75 f4 ff 75 f8 e8 0d 01 00 00 68 00 80 00 00 6a 00 ff 75 fc ff 55 e8 ff 75 f8 ff 75 f8 e8 0e 00 00 00 8b 45 f8 03 40 3c 8b 40 28 03 45 f8 ff e0 } //00 00 
	condition:
		any of ($a_*)
 
}