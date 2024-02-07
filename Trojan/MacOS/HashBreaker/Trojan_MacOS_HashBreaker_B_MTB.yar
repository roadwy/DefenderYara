
rule Trojan_MacOS_HashBreaker_B_MTB{
	meta:
		description = "Trojan:MacOS/HashBreaker.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {bf 02 00 00 00 e8 a8 71 00 00 48 8d 3d b8 85 00 00 48 8d 95 40 ff ff ff 48 89 fe 31 c0 e8 06 71 00 00 48 98 48 8d 0d 39 88 fe ff 48 8d 14 08 48 8b b5 40 ff ff ff 48 89 35 77 3e 01 00 48 89 15 60 3e 01 00 48 89 15 61 3e 01 00 0f b7 14 08 66 89 95 3c ff ff ff 8a 5c 08 02 88 9d 3e ff ff ff 48 01 c8 48 83 c0 03 48 89 05 3e 3e 01 00 80 fa 4b 0f 85 39 05 00 00 } //01 00 
		$a_01_1 = {bf 02 00 00 00 e8 3c 24 00 00 48 8d 3d 68 33 00 00 48 8d 95 40 ff ff ff 48 89 fe 31 c0 e8 ca 23 00 00 48 63 d0 48 8d 35 78 b4 fe ff 48 8d 04 32 48 89 05 0d da 00 00 48 89 05 0e da 00 00 8a 1c 32 8a 4c 32 01 8a 44 32 02 48 01 f2 48 83 c2 03 48 89 15 f5 d9 00 00 80 fb 4b 0f 85 5b 06 00 00 } //01 00 
		$a_01_2 = {4e 55 49 54 4b 41 5f 4f 4e 45 46 49 4c 45 5f 50 41 52 45 4e 54 } //00 00  NUITKA_ONEFILE_PARENT
	condition:
		any of ($a_*)
 
}