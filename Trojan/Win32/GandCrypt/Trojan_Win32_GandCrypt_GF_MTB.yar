
rule Trojan_Win32_GandCrypt_GF_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 4d e0 81 7d e0 4e ce 21 00 7d 90 01 01 81 7d e0 e8 a7 03 00 75 90 01 01 68 90 01 04 ff 15 90 01 04 a3 90 01 04 81 3d 90 01 04 0b 12 00 00 75 90 01 01 8d 95 9c f3 ff ff 52 6a 00 ff 15 90 01 04 eb 90 01 01 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}