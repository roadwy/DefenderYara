
rule Trojan_Win32_CryptInject_PVD_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {8a 14 19 88 14 38 8a 83 90 01 04 84 c0 75 90 01 01 a1 90 01 04 8a 0d 90 01 04 03 c3 03 c7 30 08 83 3d 90 01 04 03 76 90 00 } //02 00 
		$a_00_1 = {8b 44 24 10 6a 24 33 d2 5f 8d 0c 06 8b c6 f7 f7 8b 44 24 0c 8a 04 02 30 01 46 3b 74 24 14 75 } //00 00 
	condition:
		any of ($a_*)
 
}