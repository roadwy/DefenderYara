
rule Trojan_Win32_Emotetcrypt_EV_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.EV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 04 08 8b f2 8b 54 24 90 01 01 8a 14 32 88 14 29 8b 54 24 90 01 01 88 04 32 8b 54 24 90 01 01 0f b6 14 0a 8b c6 2b 44 24 90 01 01 bd 90 01 04 0f b6 04 18 03 c2 33 d2 f7 f5 8b 6c 24 90 01 01 03 54 24 90 01 01 0f b6 04 1a 30 44 2f ff 90 00 } //01 00 
		$a_03_1 = {8a 04 08 8b f2 8b 54 24 90 01 01 0f b6 14 32 88 14 29 8b 54 24 90 01 01 88 04 32 8b 44 24 90 01 01 0f b6 04 30 8b 54 24 90 01 01 0f b6 14 0a 03 c2 33 d2 bd 90 01 04 f7 f5 8b 44 24 90 01 01 03 54 24 90 01 01 0f b6 14 02 30 54 3b ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}