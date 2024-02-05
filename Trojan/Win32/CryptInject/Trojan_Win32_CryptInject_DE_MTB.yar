
rule Trojan_Win32_CryptInject_DE_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {0f b6 c8 33 4d fc 89 4d fc 8b 55 08 83 c2 01 89 55 08 c7 45 f8 00 00 00 00 eb 09 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00 
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CryptInject_DE_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.DE!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 8b f8 32 40 00 8a c1 0a cc 22 c4 f6 d0 22 c1 43 8a e0 88 24 3e 83 fb 04 72 e5 } //00 00 
	condition:
		any of ($a_*)
 
}