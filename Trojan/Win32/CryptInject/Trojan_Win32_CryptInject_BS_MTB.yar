
rule Trojan_Win32_CryptInject_BS_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 02 83 45 90 02 03 6a 00 e8 90 01 04 8b d8 83 c3 90 01 01 6a 00 e8 90 01 04 2b d8 01 5d 90 01 01 8b 45 90 01 01 3b 45 90 01 01 72 90 0a 40 00 01 02 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CryptInject_BS_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {3d 32 d0 13 00 7c 90 01 01 81 05 90 01 04 c1 3b 0f 00 90 00 } //01 00 
		$a_02_1 = {81 ec 00 04 00 00 53 56 57 8b fa 33 f6 8b d9 85 ff 7e 90 01 01 55 8b 2d 90 01 04 8d 9b 00 00 00 00 e8 90 01 04 30 04 1e 81 ff 79 06 00 00 75 90 01 01 8d 44 24 10 50 6a 00 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}