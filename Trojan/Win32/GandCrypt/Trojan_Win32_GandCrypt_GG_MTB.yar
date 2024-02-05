
rule Trojan_Win32_GandCrypt_GG_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {b8 5f 33 00 00 85 c0 74 90 01 01 8b 4d f8 3b 0d 90 01 04 72 90 01 01 eb 90 01 01 8b 75 f8 03 75 f0 68 50 11 00 00 ff 15 90 01 04 03 f0 8b 55 f8 03 55 f0 8b 45 fc 8b 4d f4 8a 0c 31 88 0c 10 8b 55 f8 83 c2 01 89 55 f8 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}