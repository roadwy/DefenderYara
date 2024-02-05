
rule Trojan_Win32_CryptInject_CN_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {0f b6 06 33 c1 c1 e9 08 0f b6 c0 33 0c 85 10 14 43 00 46 83 ea 01 75 e8 } //01 00 
		$a_00_1 = {8b 06 33 c3 83 e0 01 31 06 8b 3d 2c 4a 43 00 42 81 c6 18 08 00 00 3b d7 72 cb } //01 00 
		$a_00_2 = {8a 04 0e 88 01 41 83 ea 01 75 f5 } //01 00 
		$a_81_3 = {32 33 34 35 53 61 66 65 54 72 61 79 2e 65 78 65 } //01 00 
		$a_81_4 = {43 3a 5c 54 45 4d 50 5c 62 66 2e 64 61 74 } //00 00 
	condition:
		any of ($a_*)
 
}