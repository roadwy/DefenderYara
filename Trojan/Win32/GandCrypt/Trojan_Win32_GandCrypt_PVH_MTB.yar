
rule Trojan_Win32_GandCrypt_PVH_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.PVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 4d f4 03 4d f0 33 c1 8b 55 f4 c1 ea 05 03 55 e0 33 c2 8b 4d dc 2b c8 89 4d dc 8b 55 f0 2b 55 e4 89 55 f0 eb 90 01 01 8b 45 d8 8b 4d dc 89 08 8b 55 d8 8b 45 f4 89 42 04 90 00 } //02 00 
		$a_02_1 = {8b 4d f8 c1 e9 05 8b 55 0c 03 4a 04 33 c1 8b 4d e4 2b c8 89 4d e4 ff 75 f0 e8 90 01 04 89 45 f0 eb 90 01 01 8b 45 08 8b 4d e4 89 08 8b 45 08 8b 4d f8 89 48 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}