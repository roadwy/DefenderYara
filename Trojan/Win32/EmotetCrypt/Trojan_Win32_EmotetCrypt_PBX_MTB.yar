
rule Trojan_Win32_EmotetCrypt_PBX_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 14 37 8a 04 2e 02 c1 02 ca 88 44 24 2c 88 0c 2e 8b 4c 24 2c 88 04 37 33 c0 81 e1 ff 00 00 00 8a 04 2e 33 d2 03 c1 f7 35 90 01 04 8b 44 24 3c 8b da 03 d8 ff 15 90 01 04 8a 14 33 8a 44 24 2c 8b 4c 24 20 02 d0 8b 44 24 28 32 14 01 88 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}