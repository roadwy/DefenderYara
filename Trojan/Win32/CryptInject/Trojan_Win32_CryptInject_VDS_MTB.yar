
rule Trojan_Win32_CryptInject_VDS_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.VDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {8a 54 24 12 08 5c 24 10 8a c2 83 25 90 01 04 00 24 fc c0 e0 04 0a f8 81 3d 90 01 04 38 13 00 00 88 7c 24 13 75 90 00 } //02 00 
		$a_02_1 = {8b 45 dc 8d 3c 10 8a 07 32 c1 39 5d c8 74 90 01 01 88 07 eb 90 01 01 88 17 90 00 } //02 00 
		$a_02_2 = {8b 4c 24 18 8b d0 d3 e2 8b c8 c1 e9 05 03 4c 24 24 03 54 24 28 c7 05 90 01 04 00 00 00 00 33 d1 8b 4c 24 14 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}