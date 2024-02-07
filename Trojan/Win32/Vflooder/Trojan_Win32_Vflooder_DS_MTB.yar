
rule Trojan_Win32_Vflooder_DS_MTB{
	meta:
		description = "Trojan:Win32/Vflooder.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba ae 64 13 74 03 3b 29 91 75 41 fd 65 ae fb 13 72 41 3d 1f 01 25 00 30 00 31 c6 ba 2f d6 d3 64 } //01 00 
		$a_01_1 = {68 3f e8 1f c6 80 34 1c 53 0e 55 e4 52 f3 e5 f8 25 e0 6a 14 8d 0c 0a 5c 33 6e 2f 46 8d 2b 22 57 e0 50 0a 59 46 } //01 00 
		$a_01_2 = {8b 14 fe ba cf 1e 89 41 08 17 a3 60 32 1c 15 05 52 68 ec af 33 9b fb 5c 10 0a 1b 48 90 a1 18 fe 1e 48 f3 50 68 00 22 38 8b 0d 19 51 68 18 b0 7b f2 7c 10 30 4c 68 98 18 6a 01 6e f6 7b f3 0c 80 85 c0 74 } //01 00 
		$a_01_3 = {05 4d 08 02 1e 6c 36 35 b3 8c e8 e8 03 0f 00 01 4d d3 6d c3 44 99 10 29 0c e8 5c 37 d3 2c 23 } //01 00 
		$a_01_4 = {34 61 33 31 39 31 62 61 31 61 66 64 65 35 32 36 31 33 } //00 00  4a3191ba1afde52613
	condition:
		any of ($a_*)
 
}