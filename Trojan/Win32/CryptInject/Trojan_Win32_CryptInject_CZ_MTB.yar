
rule Trojan_Win32_CryptInject_CZ_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d cc 03 8d 90 02 04 89 4d cc 8b 95 90 02 04 33 55 cc 89 95 90 00 } //01 00 
		$a_03_1 = {8b 4d b8 8b 14 81 2b 55 cc 8b 85 90 02 04 8b 4d d8 89 14 81 e9 90 00 } //02 00 
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}