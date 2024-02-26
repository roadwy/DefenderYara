
rule Trojan_Win32_CryptInject_MZF_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.MZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 54 24 24 8b 6c 24 28 c7 44 24 2c 90 01 04 8b 44 24 2c 83 c4 0c 8a 0c 17 30 0c 06 47 40 3b fd 72 90 00 } //01 00 
		$a_03_1 = {8b f9 8b 4d e0 c1 e9 10 c1 e8 08 0f b6 c9 33 1c 8d 90 01 04 0f b6 c0 33 1c 85 90 01 04 0f b6 c2 33 1c 85 90 01 04 8b 45 10 33 5e 2c 8b 55 f0 89 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}