
rule Trojan_Win32_CryptInject_A_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e0 00 81 6d fc 90 01 04 81 45 fc 90 01 04 c1 e8 90 01 01 81 6d fc 90 01 04 c1 e0 90 01 01 81 45 fc 90 01 04 b8 90 01 04 81 6d fc 90 01 04 35 90 01 04 81 45 fc 90 01 04 c1 eb 90 01 01 81 45 fc 90 01 04 d1 e3 d1 e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CryptInject_A_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 83 e0 0f 0f b6 80 90 01 04 30 81 90 01 04 8d 82 90 01 04 03 c1 83 e0 0f 0f b6 80 90 01 04 30 81 90 01 04 8d 86 90 01 04 03 c1 83 e0 0f 0f b6 80 90 01 04 30 81 90 01 04 8d 87 90 01 04 03 c1 83 e0 0f 0f b6 80 90 01 04 30 81 90 01 04 8d 83 90 01 04 03 c1 83 e0 0f 0f b6 80 90 01 04 30 81 90 01 04 83 c1 05 81 f9 00 66 0d 00 72 90 00 } //01 00 
		$a_81_1 = {72 75 6e 44 6c 6c 46 72 6f 6d 4d 65 6d 6f 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}