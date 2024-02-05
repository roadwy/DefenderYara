
rule Trojan_Win32_GandCrypt_PVJ_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.PVJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b ce c1 e9 05 03 0d 90 01 04 50 33 d1 8d 0c 30 33 d1 2b fa e8 90 01 04 4b 75 90 01 01 8b 44 24 1c 89 38 5f 89 70 04 5e 5d 5b 83 c4 08 c2 04 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}