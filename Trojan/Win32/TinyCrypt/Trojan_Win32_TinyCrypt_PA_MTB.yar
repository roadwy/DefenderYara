
rule Trojan_Win32_TinyCrypt_PA_MTB{
	meta:
		description = "Trojan:Win32/TinyCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 c8 83 c0 01 89 45 c8 81 7d c8 90 02 04 73 64 8b 4d c8 8b 55 d4 8b 04 8a 89 45 88 8b 0d 90 02 04 89 4d 8c 8b 55 88 2b 55 c8 89 55 88 8b 45 e0 90 00 } //01 00 
		$a_02_1 = {99 b9 00 00 09 00 f7 f9 89 90 01 01 e0 8b 55 90 01 01 33 55 90 01 01 89 55 90 01 01 8b 90 01 01 e0 2d 00 10 00 00 89 90 01 01 e0 c1 45 90 01 01 07 8b 90 01 01 e0 c1 e1 90 01 01 89 4d e0 8b 55 90 01 01 33 55 90 01 01 89 55 90 01 01 8b 45 90 01 01 8b 4d f4 8b 55 90 01 01 89 14 81 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}