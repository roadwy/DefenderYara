
rule Trojan_Win32_CryptInject_YM_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 0c 53 c7 45 f8 06 ba ec 9e 81 45 f8 24 d1 fd 2b 35 b8 43 2b 27 81 45 f8 d6 74 15 35 c1 e3 11 81 45 f8 fd 43 03 00 a1 90 01 03 00 0f af 45 f8 83 65 fc 00 a3 90 01 03 00 bb 7b 1f be 69 81 6d fc 78 b1 af 32 81 45 fc 78 b1 af 32 81 f3 3e ff 7f 22 35 9b fe b9 69 81 45 fc c3 9e 26 00 a1 90 01 03 00 03 45 fc 83 65 f4 00 a3 90 01 03 00 81 f3 d2 ab 0e 49 81 6d f4 98 18 6f 3c 81 45 f4 a8 18 6f 3c 8b 4d f4 d3 e8 5b 25 ff 7f 00 00 c9 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}