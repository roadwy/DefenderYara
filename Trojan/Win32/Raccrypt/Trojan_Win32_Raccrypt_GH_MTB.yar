
rule Trojan_Win32_Raccrypt_GH_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {52 b8 6c 00 00 00 6a 00 c7 05 90 01 04 6c 00 33 00 c7 05 90 01 04 6b 00 65 00 c7 05 90 01 04 6e 00 65 00 66 a3 90 01 04 89 0d 90 01 04 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GH_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {b4 21 e1 c5 c7 05 90 01 04 ff ff ff ff 90 0a 32 00 c1 90 01 01 04 90 02 0f c1 90 01 01 05 90 02 0f 90 17 02 01 01 31 33 90 02 0f 90 17 02 01 01 31 33 90 01 01 c7 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GH_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 03 44 24 90 01 01 51 8d 4c 24 14 c7 05 90 01 04 b4 02 d7 cb c7 05 90 01 04 ff ff ff ff 89 44 24 90 01 01 e8 90 01 04 8b 54 24 90 01 01 52 8d 4c 24 90 01 01 e8 90 01 04 2b 74 24 90 01 01 8d 44 24 90 01 01 89 74 24 90 01 01 e8 90 01 04 4d 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GH_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 90 0a 7d 00 c6 05 90 01 04 6f c6 05 90 01 04 74 c6 05 90 01 04 00 c6 05 90 01 04 50 c6 05 90 01 04 61 c6 05 90 01 04 65 c6 05 90 01 04 75 c6 05 90 01 04 6c c6 05 90 01 04 69 c6 05 90 01 04 63 c6 05 90 01 04 74 c6 05 90 01 04 74 c6 05 90 01 04 72 c6 05 90 01 04 56 c6 05 90 01 04 72 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}