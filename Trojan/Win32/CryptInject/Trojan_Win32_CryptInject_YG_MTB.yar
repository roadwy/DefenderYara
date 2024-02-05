
rule Trojan_Win32_CryptInject_YG_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 55 08 8b 0a 0f b6 14 01 03 c8 88 55 fe 0f b6 51 01 88 55 fd 0f b6 51 02 88 55 fc 8a 51 03 89 5d f8 83 45 f8 02 89 5d f4 83 45 f4 04 8b 4d f8 8a da d2 e3 8b 4d f4 80 e3 c0 0a 5d fe 88 1c 3e 8a da d2 e3 c0 e2 06 0a 55 fc 80 e3 c0 0a 5d fd 80 ea 02 88 5c 3e 01 88 55 ff 80 45 ff 02 8a 4d ff 88 4c 3e 02 8b 4d 0c 83 c0 04 83 c6 03 3b 01 72 8c } //00 00 
	condition:
		any of ($a_*)
 
}