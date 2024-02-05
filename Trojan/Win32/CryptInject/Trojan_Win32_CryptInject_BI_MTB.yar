
rule Trojan_Win32_CryptInject_BI_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c8 0b 98 7f b8 c6 ee 57 15 81 45 90 01 01 be 6c 90 01 01 28 81 e3 15 2d 0d 0f 81 6d 90 01 01 36 18 c4 05 81 f3 26 ed 5f 56 81 45 90 01 01 40 b7 cb 5c a1 90 01 04 8b 5d 90 01 01 33 f2 3d 9b 04 00 00 75 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CryptInject_BI_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {f6 da 32 c2 d2 fc 80 c2 e0 0f bb d0 80 f2 75 66 35 bd 0d 66 81 fa ce 01 c1 f8 88 32 da c0 e4 8c 12 c0 d3 e8 89 0c 14 f9 8b 07 8d bf 04 00 00 00 e9 } //02 00 
		$a_01_1 = {f7 da 42 81 f2 81 3a eb 41 d1 ca 66 f7 c1 8c 0b 80 fa 45 33 da f9 03 f2 e9 } //00 00 
	condition:
		any of ($a_*)
 
}