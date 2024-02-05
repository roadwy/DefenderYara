
rule Trojan_Win32_TrickBotCrypt_DR_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 04 32 33 d2 8a 14 37 03 c2 33 d2 f7 35 90 01 04 8a c3 b3 1f f6 2d 90 01 04 f6 eb 8a 14 32 2a d0 a0 90 01 04 f6 eb 02 d0 a0 90 01 04 2a d0 8b 44 24 90 01 01 8a 1c 01 32 da 88 1c 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}