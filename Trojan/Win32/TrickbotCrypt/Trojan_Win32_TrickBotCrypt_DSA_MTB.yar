
rule Trojan_Win32_TrickBotCrypt_DSA_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 14 37 0f b6 c0 03 c2 33 d2 f7 f1 8b 44 24 20 8b da 03 d8 ff 15 90 01 04 8a 0c 33 8a 44 24 28 8b 54 24 1c 02 c8 8b 44 24 14 32 0c 02 88 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}