
rule Trojan_Win32_GandCrypt_KMG_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.KMG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 e0 04 03 45 e4 8b 4d f8 03 4d f4 33 c1 8b 55 f8 c1 ea 05 03 55 e0 33 c2 8b 4d fc 2b c8 89 4d fc 8b 55 dc 83 ea 01 8b 45 f4 2b c2 89 45 f4 eb } //00 00 
	condition:
		any of ($a_*)
 
}