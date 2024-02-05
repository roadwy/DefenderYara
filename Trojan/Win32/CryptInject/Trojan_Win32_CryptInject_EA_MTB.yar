
rule Trojan_Win32_CryptInject_EA_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {89 45 0c 8b 45 e4 01 45 0c 8b 45 0c 33 45 f8 33 c1 2b f0 81 3d 90 02 04 93 00 00 00 74 0e 68 b9 79 37 9e 8d 45 f4 50 e8 90 02 04 ff 4d f0 0f 85 90 00 } //02 00 
		$a_03_1 = {03 fb 03 c6 33 cf 33 c8 89 45 f8 89 4d 0c 8b 45 0c 01 05 90 02 04 8b 45 0c 29 45 fc 8b 4d fc c1 e1 04 03 4d ec 8b 45 fc 03 45 f4 89 45 f8 90 00 } //01 00 
		$a_01_2 = {81 fe 6e 27 87 01 7f 0d 46 81 fe f6 ea 2b 33 0f 8c } //00 00 
	condition:
		any of ($a_*)
 
}