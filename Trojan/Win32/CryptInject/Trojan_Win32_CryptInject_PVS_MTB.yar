
rule Trojan_Win32_CryptInject_PVS_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {8d 04 33 33 c8 2b f9 8b cf 8b c7 c1 e9 05 03 0d 90 01 04 c1 e0 04 03 05 90 01 04 33 c8 8d 04 3b 2b 5c 24 10 33 c8 2b f1 45 83 fd 20 72 90 00 } //02 00 
		$a_02_1 = {8a 4c 18 03 8a e9 88 4d ff 80 e5 f0 8a d1 80 e2 fc c0 e5 02 0a 2c 18 c0 e2 04 0a 54 18 01 83 3d 90 01 04 2c 88 6d fe 88 55 fd 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}