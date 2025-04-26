
rule Trojan_Win32_StopCrypt_DC_MTB{
	meta:
		description = "Trojan:Win32/StopCrypt.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b f8 89 7c 24 2c c7 44 24 20 [0-04] 8b 44 24 10 01 44 24 20 8b 44 24 2c 01 44 24 20 8b 44 24 20 89 44 24 1c 8b 4c 24 24 8b d7 d3 ea 89 54 24 14 8b 44 24 3c 01 44 24 14 8b f7 c1 e6 04 03 74 24 40 33 74 24 1c 81 3d [0-08] 75 } //2
		$a_03_1 = {c7 44 24 48 a2 86 7a 5c c7 44 24 0c 6e b7 1b 45 c7 84 24 0c 01 00 00 af 55 a9 41 89 54 24 04 b8 [0-04] 01 44 24 04 8b 44 24 04 8a 04 30 88 04 0e 46 3b 35 [0-04] 0f } //1
		$a_01_2 = {81 fe 9d 94 30 00 7f 0d 46 81 fe 5a 5b 1b 02 0f } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}