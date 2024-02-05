
rule Trojan_Win32_GandCrypt_PVF_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.PVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 45 e0 8b 5d d4 89 38 8b 45 dc 89 30 8b 45 f8 40 89 45 f8 3b 45 d8 0f 82 90 01 04 5f 5e 5b 8b e5 5d c3 90 00 } //02 00 
		$a_02_1 = {8b c3 c1 e9 05 03 4d f0 c1 e0 04 03 45 ec 33 c8 8d 04 1e 33 c8 8d b6 90 01 04 2b f9 83 6d fc 01 75 90 01 01 8b 75 e8 89 3e 5f 89 5e 04 5e 5b 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}