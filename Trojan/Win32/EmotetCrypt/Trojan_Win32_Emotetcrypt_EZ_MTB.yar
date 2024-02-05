
rule Trojan_Win32_Emotetcrypt_EZ_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 04 08 8b 6c 24 90 01 01 8b f2 8b 54 24 90 01 01 8a 14 32 88 14 29 8b 54 24 90 01 01 88 04 32 8b 44 24 90 01 01 0f b6 04 30 8b 54 24 90 01 01 0f b6 14 0a 03 c2 33 d2 bd 90 01 04 f7 f5 8b 44 24 90 01 01 8b 6c 24 90 01 01 03 54 24 90 01 01 03 d7 8a 04 02 30 04 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}