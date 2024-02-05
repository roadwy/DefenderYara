
rule Trojan_Win32_CryptInject_AB_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {69 c0 fd 43 03 00 05 c3 9e 26 00 56 a3 90 01 04 0f b7 35 90 01 04 81 e6 ff 7f 00 00 81 3d 90 01 04 e7 08 00 00 90 00 } //01 00 
		$a_03_1 = {81 fb 85 02 00 00 75 90 01 01 56 56 56 56 56 ff 15 90 01 04 56 56 56 56 ff 15 90 01 04 e8 90 01 04 30 04 2f 81 fb 91 05 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CryptInject_AB_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {33 c1 66 89 45 88 0f b7 55 ec 0f b7 45 d4 0b d0 66 89 55 d0 8b 4d b8 0f b6 11 0f b6 4d fe d3 fa 88 55 fa } //01 00 
		$a_03_1 = {8b 01 33 02 89 85 90 01 04 8a 4d a9 88 4d 82 90 00 } //01 00 
		$a_03_2 = {33 ca 66 89 8d 90 01 04 8b 85 90 01 04 8b 95 90 01 04 8b 08 d3 ea 8b 85 90 01 04 89 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}