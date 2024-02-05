
rule Trojan_Win32_CryptInject_BO_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c4 04 8b 15 90 01 04 89 15 90 01 04 a1 90 01 04 8b 0d 90 01 04 8d 54 01 03 2b 55 d4 03 15 90 01 04 89 15 90 01 04 a1 90 01 04 83 e8 03 a3 90 01 04 8b 0d 90 01 04 2b 0d 90 01 04 89 0d 90 01 04 8b 15 90 01 04 03 15 90 01 04 89 15 90 01 04 83 3d 90 01 04 00 0f 90 00 } //01 00 
		$a_02_1 = {8b 65 fc a1 90 01 04 58 8b e8 a1 90 01 04 ff 35 90 01 04 a1 90 01 04 ff 35 90 01 04 a1 90 01 04 8b 15 90 01 04 8b 15 90 01 04 8b 15 90 01 04 8b 15 90 01 04 8b 15 90 01 04 ff 25 90 01 04 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}