
rule Trojan_Win32_StopCrypt_DY_MTB{
	meta:
		description = "Trojan:Win32/StopCrypt.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {2b d8 89 5d e4 89 75 ec 8b 45 fc 01 45 ec 8b 45 e4 01 45 ec 8b 45 ec 89 45 f0 8b 4d e8 8b c3 d3 e8 89 45 f8 8b 45 d0 01 45 f8 8b f3 c1 e6 04 03 75 d8 33 75 f0 81 3d 90 02 08 75 0b 90 00 } //01 00 
		$a_01_1 = {81 84 24 94 02 00 00 e3 9b 81 29 81 ac 24 d8 00 00 00 90 97 0c 2e 81 84 24 64 01 00 00 6e 1d e0 05 81 84 24 40 02 00 00 8c a8 ce 53 81 84 24 8c 01 00 00 be d1 ac 2e 81 ac 24 64 01 00 00 62 46 5d 36 81 84 24 2c 02 00 00 e9 3a 71 34 81 84 24 d8 00 00 00 c6 08 dc 32 81 84 24 2c 02 00 00 17 62 f9 54 } //01 00 
		$a_01_2 = {81 ff aa b0 e7 00 7f 0d 47 81 ff 76 24 ec 5a 0f 8c } //00 00 
	condition:
		any of ($a_*)
 
}