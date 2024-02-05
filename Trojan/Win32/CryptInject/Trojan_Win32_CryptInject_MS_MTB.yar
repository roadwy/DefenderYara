
rule Trojan_Win32_CryptInject_MS_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b ec 83 c4 90 01 01 51 53 52 57 ff 75 90 01 01 58 85 c0 74 90 01 01 33 db 33 d2 bf 90 01 04 b9 01 00 00 00 d1 c0 8a dc 8a e6 d1 cb 8b 4d 90 01 01 4f 75 90 01 01 c1 cb 90 01 01 8b c3 5f 5a 5b 59 c9 c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CryptInject_MS_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.MS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 d8 2d 00 10 00 00 89 45 d8 c7 45 fc 00 00 00 00 83 e6 3b 2b f3 86 e9 83 fe 3a 8d bd d4 ff ff ff 03 1f ba 01 00 00 00 66 8b c3 83 f9 0f 33 c0 8b 4d d8 66 8b 01 3b 45 cc } //00 00 
	condition:
		any of ($a_*)
 
}