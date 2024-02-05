
rule Trojan_MacOS_Xcsset_C_MTB{
	meta:
		description = "Trojan:MacOS/Xcsset.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {0f b6 05 19 7e 00 00 89 c1 48 8d 15 1e 7e 00 00 40 8a 34 0a 40 88 75 f3 0f b6 45 f3 0f b6 3d fb 7d 00 00 01 c7 40 88 3d f2 7d 00 00 48 8b 4d e8 0f b6 05 e9 7d 00 00 48 89 55 e0 99 f7 7d f4 4c 63 c2 42 0f b6 14 01 44 0f b6 0d cf 7d 00 00 41 01 d1 44 88 0d c5 7d 00 00 0f b6 15 be 7d 00 00 89 d1 4c 8b 45 e0 41 8a 34 08 0f b6 15 af 7d 00 00 89 d1 41 88 34 08 40 8a 75 f3 0f b6 15 9c 7d 00 00 89 d1 41 88 34 08 8a 05 92 7d 00 00 04 01 88 05 8a 7d 00 00 3c 00 0f 85 62 ff ff ff 48 8b 45 e8 48 05 00 01 00 00 48 89 45 e8 8b 4d f4 81 e9 00 01 00 00 89 4d f4 e9 34 ff ff ff } //01 00 
		$a_00_1 = {8a 05 2f 7d 00 00 04 01 88 05 27 7d 00 00 0f b6 0d 20 7d 00 00 89 ca 48 8d 35 25 7d 00 00 8a 04 16 88 45 f3 0f b6 4d f3 0f b6 3d 05 7d 00 00 01 cf 40 88 3d fc 7c 00 00 0f b6 0d f5 7c 00 00 89 ca 8a 04 16 0f b6 0d ea 7c 00 00 89 ca 88 04 16 8a 45 f3 0f b6 0d da 7c 00 00 89 ca 88 04 16 0f b6 0d cf 7c 00 00 89 ca 0f b6 0c 16 44 0f b6 45 f3 41 01 c8 44 88 45 f3 0f b6 4d f3 89 ca 0f b6 0c 16 48 8b 55 e8 44 0f b6 0a 41 31 c9 44 88 0a 48 8b 55 e8 48 81 c2 01 00 00 00 48 89 55 e8 8b 4d f4 83 c1 ff 89 4d f4 } //00 00 
	condition:
		any of ($a_*)
 
}